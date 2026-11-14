#!/usr/bin/env python3
"""Сборка локального поискового индекса по датасету HF (data/hf_cyber.db).

Тексты в индекс не копируются: FTS5 без содержимого + адрес записи в файле (байтовое смещение или
JSON-указатель). При поиске сами записи читаются с HF Range-запросами. Индекс можно дособирать:
уже проиндексированные файлы пропускаются.

  .venv/bin/python -m secreqs.sources.hf_cyber.build_index                 # всё, кроме файлов > 1 ГБ
  .venv/bin/python -m secreqs.sources.hf_cyber.build_index --max-mb 50     # только небольшие файлы
  .venv/bin/python -m secreqs.sources.hf_cyber.build_index --only master   # по регулярке пути
  .venv/bin/python -m secreqs.sources.hf_cyber.build_index --list          # что будет проиндексировано
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from secreqs.core import write_status
from secreqs.sources.hf_cyber import client as C
from secreqs.sources.hf_cyber import records as R

DB = C.DB
SMALL = 8_000_000      # JSON меньше этого разбирается целиком (записи адресуются JSON-указателем)
BODY_LIMIT = 30000     # сколько текста записи попадает в индекс

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, size INTEGER, category TEXT, kind TEXT,
  records INTEGER, seconds REAL, indexed_at TEXT);
CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY, path TEXT, category TEXT, kind TEXT,
  offset INTEGER, length INTEGER, pointer TEXT, title TEXT);
CREATE INDEX IF NOT EXISTS docs_path ON docs(path);
CREATE INDEX IF NOT EXISTS docs_cat ON docs(category);
CREATE TABLE IF NOT EXISTS cves(cve TEXT, doc_id INTEGER);
CREATE INDEX IF NOT EXISTS cves_cve ON cves(cve);
CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(title, body, content='',
  tokenize='porter unicode61 remove_diacritics 2');
"""


def plan(max_mb: float, only: str | None, refresh: bool) -> list[dict]:
    files = [f for f in C.dedupe(C.list_files(refresh)) if C.is_text_file(f["path"])]
    if only:
        files = [f for f in files if re.search(only, f["path"], re.I)]
    return sorted([f for f in files if f["size"] <= max_mb * 1e6], key=lambda f: f["size"])


def records_of(f: dict):
    """(kind, offset, length, pointer, obj_or_text) для всех записей файла."""
    path, size = f["path"], f["size"]
    if path.endswith(".jsonl"):
        for off, n, obj, raw in R.iter_jsonl(C.open_stream(path)):
            yield "range", off, n, None, obj if obj is not None else raw.decode("utf-8", "replace")
    elif path.endswith(".json") and size > SMALL:
        for off, n, obj in R.iter_json_array(C.open_stream(path)):
            yield "range", off, n, None, obj
    elif path.endswith(".json"):
        data = C.read_small(path, SMALL)
        try:
            obj = json.loads(data)
        except ValueError:
            yield "file", 0, len(data), None, data.decode("utf-8", "replace")
            return
        for ptr, x in R.explode_json(obj):
            yield "json", 0, 0, json.dumps(ptr), x
    elif path.endswith(".csv"):
        for off, n, line in R.iter_lines(C.open_stream(path)):
            yield "range", off, n, None, line
    else:  # .md / .txt — файл целиком
        data = C.read_small(path, SMALL)
        yield "file", 0, len(data), None, data.decode("utf-8", "replace")


def prepare(f):
    """Скачать и разобрать небольшой файл в потоке-воркере."""
    t = time.time()
    try:
        return f, list(records_of(f)), time.time() - t, None
    except Exception as e:
        return f, None, time.time() - t, repr(e)[:300]


def store(con, f, recs, seconds, next_id):
    next_id, n = _store_batch(con, f, recs, next_id)
    _mark_done(con, f, n, seconds)
    return next_id, n


def _mark_done(con, f, n, seconds):
    con.execute("INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,datetime('now'))",
                (f["path"], f["size"], C.category_of(f["path"]), os.path.splitext(f["path"])[1], n,
                 round(seconds, 1)))
    con.commit()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-mb", type=float, default=1000)
    ap.add_argument("--only")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--refresh", action="store_true", help="перечитать список файлов с HF")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)

    files = plan(a.max_mb, a.only, a.refresh)
    if a.list:
        for f in files:
            print(f"{f['size'] / 1e6:10.2f} MB  {f['path']}")
        print(f"# {len(files)} файлов, {sum(f['size'] for f in files) / 1e9:.2f} ГБ", file=sys.stderr)
        return

    os.makedirs(os.path.dirname(DB), exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute("PRAGMA journal_mode=WAL")  # MCP-сервер может искать, пока индекс дособирается
    con.executescript(SCHEMA)
    con.execute("INSERT OR REPLACE INTO meta VALUES('repo', ?)", (C.REPO,))
    con.execute("INSERT OR REPLACE INTO meta VALUES('revision', ?)", (C.REVISION,))
    # Переиндексация файла не поддерживается: в FTS5 без содержимого удаление требует исходного текста.
    # Чтобы пересобрать — удалить data/hf_cyber.db.
    done = {r[0] for r in con.execute("SELECT path FROM files")}
    todo = [f for f in files if f["path"] not in done]
    next_id = (con.execute("SELECT max(id) FROM docs").fetchone()[0] or 0) + 1
    print(f"к индексации {len(todo)} файлов, {sum(f['size'] for f in todo) / 1e9:.2f} ГБ "
          f"(уже в индексе: {len(done)})", flush=True)

    small = [f for f in todo if f["size"] <= SMALL or not f["path"].endswith((".json", ".jsonl", ".csv"))]
    big = [f for f in todo if f not in small]
    errors = 0
    t0 = time.time()
    with ThreadPoolExecutor(a.workers) as ex:
        for i, (f, recs, sec, err) in enumerate(ex.map(prepare, small), 1):
            if err:
                errors += 1
                print(f"  ! {f['path']}: {err}", flush=True)
                continue
            next_id, n = store(con, f, recs, sec, next_id)
            if i % 100 == 0 or i == len(small):
                print(f"  небольшие файлы: {i}/{len(small)}, {time.time() - t0:.0f} с", flush=True)
    for f in big:  # крупные — по одному, потоково, с прогрессом
        t = time.time()
        print(f"  {f['path']} ({f['size'] / 1e6:.0f} МБ)…", flush=True)
        try:
            # пишем пачками, чтобы не держать гигабайт записей в памяти; коммит — только в конце файла
            n_total, batch = 0, []
            for rec in records_of(f):
                batch.append(rec)
                if len(batch) >= 5000:
                    next_id, n = _store_batch(con, f, batch, next_id)
                    n_total += n
                    batch = []
                    if n_total % 50000 < 5000:
                        print(f"    {n_total} записей, {time.time() - t:.0f} с", flush=True)
            next_id, n = _store_batch(con, f, batch, next_id)
            n_total += n
            _mark_done(con, f, n_total, time.time() - t)
            print(f"    готово: {n_total} записей за {time.time() - t:.0f} с", flush=True)
        except Exception as e:
            con.rollback()  # файл целиком откатывается и будет взят при следующем запуске
            next_id = (con.execute("SELECT max(id) FROM docs").fetchone()[0] or 0) + 1
            errors += 1
            print(f"  ! {f['path']}: {e!r}"[:400], flush=True)
    if todo:  # на 2,5 ГБ индекса optimize идёт минуты — только если что-то добавили
        con.execute("INSERT INTO docs_fts(docs_fts) VALUES('optimize')")
        con.commit()
    nd, nf = con.execute("SELECT (SELECT count(*) FROM docs), (SELECT count(*) FROM files)").fetchone()
    con.close()
    write_status("hf_cyber", {"files": nf, "records": nd, "errors": errors, "planned": len(files),
                              "missing": len(files) - nf if len(files) > nf else 0})
    print(f"{DB}: {nf} файлов, {nd} записей, {os.path.getsize(DB) / 1e6:.0f} МБ, ошибок: {errors}, "
          f"{time.time() - t0:.0f} с")


def _store_batch(con, f, batch, next_id):
    cat = C.category_of(f["path"])
    n = 0
    for kind, off, length, ptr, x in batch:
        body = R.text_of(x, BODY_LIMIT)
        if not body.strip():
            continue
        title = R.title_of(x, fallback=body[:200])
        con.execute("INSERT INTO docs VALUES(?,?,?,?,?,?,?,?)", (next_id, f["path"], cat, kind, off, length, ptr, title))
        con.execute("INSERT INTO docs_fts(rowid, title, body) VALUES(?,?,?)", (next_id, title, body))
        cves = R.cves_in(title + "\n" + body)
        if cves:
            con.executemany("INSERT INTO cves VALUES(?,?)", [(c, next_id) for c in cves])
        next_id += 1
        n += 1
    return next_id, n


if __name__ == "__main__":
    main()
