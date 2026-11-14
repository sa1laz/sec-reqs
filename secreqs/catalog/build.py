#!/usr/bin/env python3
"""Сборка каталога требований.

  .venv/bin/python -m secreqs.catalog.build                 # все загрузчики + база
  .venv/bin/python -m secreqs.catalog.build stig scuba      # только эти загрузчики + база
  .venv/bin/python -m secreqs.catalog.build --db-only       # пересобрать базу из готовых JSONL
  .venv/bin/python -m secreqs.catalog.build --list

Ошибка одного загрузчика не останавливает остальные: его прошлый JSONL (если был) остаётся в базе.
"""
from __future__ import annotations

import argparse
import glob
import importlib
import json
import os
import re
import sqlite3
import sys
import time
import traceback

from secreqs.catalog.loaders import LOADERS
from secreqs.catalog.model import OUT
from secreqs.core import DATA

DB = os.environ.get("CATALOG_DB", os.path.join(DATA, "catalog.db"))

SCHEMA = """
CREATE TABLE frameworks(id TEXT PRIMARY KEY, title TEXT, version TEXT, published TEXT, kind TEXT, publisher TEXT,
  license TEXT, url TEXT, description TEXT, n_documents INTEGER, n_items INTEGER, loader TEXT, built_at TEXT);
CREATE TABLE documents(framework TEXT, id TEXT, title TEXT, version TEXT, date TEXT, url TEXT, description TEXT,
  extra TEXT, n_items INTEGER, title_norm TEXT, PRIMARY KEY(framework, id));
CREATE TABLE items(rowid INTEGER PRIMARY KEY, uid TEXT UNIQUE, framework TEXT, document TEXT, item_id TEXT,
  title TEXT, kind TEXT, parent TEXT, severity TEXT, profiles TEXT, text TEXT, refs TEXT, extra TEXT, sort_key TEXT);
CREATE INDEX items_doc ON items(framework, document, sort_key);
CREATE INDEX items_id ON items(item_id);
CREATE TABLE maps(uid TEXT, ns TEXT, target TEXT, rel TEXT);
CREATE INDEX maps_uid ON maps(uid);
CREATE INDEX maps_target ON maps(ns, target);
CREATE TABLE self_ids(uid TEXT, ns TEXT, target TEXT);   -- под какими id элемент известен в пространствах имён
CREATE INDEX self_ids_t ON self_ids(ns, target);
CREATE TABLE cve_scores(cve TEXT, source TEXT, score REAL, percentile REAL, date TEXT);
CREATE VIRTUAL TABLE items_fts USING fts5(title, body, content='', tokenize='porter unicode61 remove_diacritics 2');
"""


def sort_key(s: str) -> str:
    return re.sub(r"\d+", lambda m: f"{int(m.group()):06d}", s.lower())


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def run_loaders(names):
    ok, failed = [], {}
    for name in names:
        mod = importlib.import_module(f"secreqs.catalog.loaders.{name}")
        t = time.time()
        print(f"[{name}] …", flush=True)
        try:
            n = mod.load()
            ok.append(name)
            print(f"[{name}] {n} элементов за {time.time() - t:.0f} с", flush=True)
        except Exception as e:
            failed[name] = repr(e)[:300]
            traceback.print_exc()
            print(f"[{name}] ОШИБКА: {e!r}"[:400], flush=True)
    return ok, failed


def build_db():
    tmp = DB + ".part"
    if os.path.exists(tmp):
        os.remove(tmp)
    con = sqlite3.connect(tmp)
    con.executescript(SCHEMA)
    rowid = 0
    for path in sorted(glob.glob(os.path.join(OUT, "*.jsonl"))):
        loader = os.path.basename(path)[:-6]
        mod = importlib.import_module(f"secreqs.catalog.loaders.{loader}") if loader in LOADERS else None
        self_ns = getattr(mod, "SELF_NS", {})   # framework → ns: элементы этого стандарта сами являются id в ns
        counts, docs = {}, {}
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            t = r["type"]
            if t == "framework":
                con.execute("INSERT OR REPLACE INTO frameworks VALUES(?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))",
                            (r["id"], r["title"], r.get("version"), r.get("published"), r["kind"], r.get("publisher"),
                             r.get("license"), r.get("url"), r.get("description"), 0, 0, loader))
            elif t == "cve_score":
                con.execute("INSERT INTO cve_scores VALUES(?,?,?,?,?)",
                            (r["cve"], r["source"], r["score"], r["percentile"], r.get("date")))
                continue
            elif t == "document":
                con.execute("INSERT OR REPLACE INTO documents VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (r["framework"], r["id"], r["title"], r.get("version"), r.get("date"), r.get("url"),
                             r.get("description"), json.dumps(r.get("extra") or {}, ensure_ascii=False), 0,
                             norm(r["title"])))
            else:
                uid = f'{r["framework"]}:{r["document"]}:{r["id"]}'
                rowid += 1
                try:
                    con.execute("INSERT INTO items VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (rowid, uid, r["framework"], r["document"], r["id"], r["title"], r["kind"],
                                 r.get("parent"), r.get("severity"), json.dumps(r["profiles"], ensure_ascii=False),
                                 json.dumps(r["text"], ensure_ascii=False), json.dumps(r["refs"], ensure_ascii=False),
                                 json.dumps(r["extra"], ensure_ascii=False), sort_key(r["id"])))
                except sqlite3.IntegrityError:
                    rowid -= 1
                    continue
                con.executemany("INSERT INTO maps VALUES(?,?,?,?)", [(uid, m["ns"], m["id"], m["rel"]) for m in r["maps"]])
                ns = self_ns.get(r["framework"])
                if ns:
                    from secreqs.catalog.model import norm_ref
                    con.execute("INSERT INTO self_ids VALUES(?,?,?)", (uid, ns, norm_ref(ns, r["id"])))
                for a in r.get("extra", {}).get("aliases", []):  # например, STIG: V-id и SV-id
                    con.execute("INSERT INTO self_ids VALUES(?,?,?)", (uid, a["ns"], a["id"]))
                body = "\n".join([r["id"]] + [v for v in r["text"].values() if v])
                con.execute("INSERT INTO items_fts(rowid, title, body) VALUES(?,?,?)", (rowid, r["title"], body[:60000]))
                counts[r["framework"]] = counts.get(r["framework"], 0) + 1
                docs[(r["framework"], r["document"])] = docs.get((r["framework"], r["document"]), 0) + 1
        for (fw, d), n in docs.items():
            con.execute("UPDATE documents SET n_items=? WHERE framework=? AND id=?", (n, fw, d))
        for fw, n in counts.items():
            nd = sum(1 for (f, _) in docs if f == fw)
            con.execute("UPDATE frameworks SET n_items=?, n_documents=? WHERE id=?", (n, nd, fw))
        con.commit()
        print(f"  {loader}: {sum(counts.values())} элементов", flush=True)
    con.execute("CREATE INDEX cve_scores_cve ON cve_scores(cve)")
    con.execute("INSERT INTO items_fts(items_fts) VALUES('optimize')")
    con.commit()
    con.execute("VACUUM")
    nf, ni, nm = con.execute("SELECT (SELECT count(*) FROM frameworks),(SELECT count(*) FROM items),"
                             "(SELECT count(*) FROM maps)").fetchone()
    con.close()
    os.replace(tmp, DB)
    print(f"{DB}: {nf} стандартов, {ni} элементов, {nm} связей, {os.path.getsize(DB) / 1e6:.0f} МБ")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("loaders", nargs="*")
    ap.add_argument("--db-only", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--if-older", type=float, metavar="DAYS",
                    help="ничего не делать, если база моложе DAYS дней (для initContainer)")
    a = ap.parse_args(argv)
    if a.list:
        for n in LOADERS:
            print(n)
        return 0
    if a.if_older is not None and os.path.exists(DB) and time.time() - os.path.getmtime(DB) < a.if_older * 86400:
        print(f"{DB} моложе {a.if_older} дн., пропускаю")
        return 0
    failed = {}
    if not a.db_only:
        names = a.loaders or LOADERS
        unknown = [n for n in names if n not in LOADERS]
        if unknown:
            sys.exit(f"неизвестные загрузчики: {unknown}; есть: {LOADERS}")
        _, failed = run_loaders(names)
    build_db()
    if failed:
        print("не загрузились:", json.dumps(failed, ensure_ascii=False, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
