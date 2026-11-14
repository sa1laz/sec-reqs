"""Источник hf_cyber: датасет Hugging Face Vyber07/cyber-security (≈95 ГБ, gated) без скачивания.

Поиск идёт по локальному индексу data/hf_cyber.db (только адреса записей и FTS без текста),
сами записи читаются с HF Range-запросами. Инструменты чтения/grep работают и без индекса.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

from mcp.server.mcpserver.exceptions import ToolError

from secreqs.core import RO_REMOTE, Source, fts_query, fts_query_or, ro_db, snippet_of
from secreqs.sources.hf_cyber import client as C
from secreqs.sources.hf_cyber import records as R

INSTRUCTIONS = f"""\
Датасет Hugging Face {C.REPO}: инструкционные и справочные данные по кибербезопасности — CVE из NVD с
CVSS/CWE (вопрос-ответ), MITRE ATT&CK (техники, группы, ПО), разборы атак и защиты, playbook'и IR,
hardening-гайды, threat hunting-запросы, комплаенс (GDPR/HIPAA/PCI DSS), фрагменты документации AWS,
описания уязвимостей OSS-Fuzz (ARVO). Качество неоднородное (часть записей сгенерирована) — для
нормативных требований опирайся на первичные источники (например, CIS), а датасет используй как
справку и для идей.
1. hf_search — полнотекстовый поиск по индексу (фильтр category из hf_overview); hf_get_record — запись целиком.
2. hf_find_cve — все записи, где упоминается CVE.
3. hf_list_files / hf_read_file / hf_grep_file — прямой доступ к файлам датасета (в т.ч. не попавшим в индекс).
"""


DB = C.DB


def db():
    return ro_db(DB)


def _load(row) -> tuple[object, str]:
    """Прочитать запись с HF по адресу из индекса → (объект, текст)."""
    if row["kind"] == "range":
        raw = C.read_range(row["path"], row["offset"], row["length"]).decode("utf-8", "replace").strip()
        try:
            obj = json.loads(raw)
        except ValueError:
            obj = raw
    elif row["kind"] == "json":
        obj = R.follow(json.loads(C.read_small(row["path"])), json.loads(row["pointer"]))
    else:
        obj = C.read_small(row["path"]).decode("utf-8", "replace")
    return obj, (obj if isinstance(obj, str) else R.text_of(obj, 200000))


def _load_many(rows):
    def one(r):
        try:
            return _load(r)
        except Exception as e:
            return None, f"(не удалось прочитать запись: {type(e).__name__})"
    with ThreadPoolExecutor(min(8, max(1, len(rows)))) as ex:
        return list(ex.map(one, rows))


def _require_index():
    if not os.path.exists(DB):
        raise ToolError("Индекс не собран: .venv/bin/python -m secreqs.sources.hf_cyber.build_index. "
                        "Пока доступны hf_list_files, hf_read_file, hf_grep_file.")


def _known_file(path: str) -> dict:
    for f in C.list_files():
        if f["path"] == path:
            return f
    raise ToolError(f"Файла «{path}» нет в датасете. Используй hf_list_files.")


def _doc_summary(r) -> dict:
    return {"id": r["id"], "title": r["title"], "category": r["category"], "file": r["path"]}


def _search_rows(con, query, category=None, path=None, limit=10):
    q = fts_query(query)
    if not q:
        raise ToolError("Пустой запрос")
    rows = []
    for qq in (q, fts_query_or(query)):
        sql = ("SELECT d.* FROM docs_fts f JOIN docs d ON d.id=f.rowid WHERE docs_fts MATCH ?")
        args = [qq]
        if category:
            sql += " AND d.category=?"
            args.append(category)
        if path:
            sql += " AND d.path LIKE ?"
            args.append(f"%{path}%")
        rows = con.execute(sql + " ORDER BY bm25(docs_fts, 5.0, 1.0) LIMIT ?", args + [limit]).fetchall()
        if rows or qq == fts_query_or(query):
            return qq, rows
    return q, rows


# ---------------------------------------------------------------- инструменты

def hf_search(query: str, category: str | None = None, file: str | None = None, limit: int = 10,
              snippets: bool = True) -> dict:
    """Полнотекстовый поиск по датасету кибербезопасности на HF.

    query: слова или "фраза в кавычках" ("kubernetes network policy", "kerberoasting detection", "CVE-2024-3094").
    Если по всем словам ничего нет, ищет по любому из слов (поле match="any").
    category: тема из hf_overview (blue-team, compliance, vulnerability-intelligence, cloud-security, …).
    file: подстрока пути файла.
    snippets: подгрузить с HF фрагменты текста (медленнее, ~1 с); без них — только заголовки.
    Возвращает id записей для hf_get_record.
    """
    _require_index()
    con = db()
    limit = max(1, min(limit, 30))
    q, rows = _search_rows(con, query, category, file, limit)
    out = [_doc_summary(r) for r in rows]
    if snippets and rows:
        for d, (_, text) in zip(out, _load_many(rows)):
            d["snippet"] = snippet_of(text, query, 300)
    return {"query": q, "match": "all" if q == fts_query(query) else "any", "results": out}


def hf_get_record(id: int, max_chars: int = 20000, raw_json: bool = False) -> dict:
    """Запись датасета целиком по id из hf_search / hf_find_cve.

    max_chars: обрезать текст (до 100000). raw_json: вернуть исходный JSON вместо плоского текста.
    """
    _require_index()
    r = db().execute("SELECT * FROM docs WHERE id=?", (id,)).fetchone()
    if not r:
        raise ToolError(f"Нет записи {id}")
    obj, text = _load(r)
    lim = max(500, min(max_chars, 100000))
    out = _doc_summary(r)
    if raw_json and not isinstance(obj, str):
        s = json.dumps(obj, ensure_ascii=False, indent=1)
        out["json"] = s[:lim]
        out["truncated"] = len(s) > lim
    else:
        out["text"] = text[:lim]
        out["truncated"] = len(text) > lim
    out["location"] = {"kind": r["kind"], "offset": r["offset"], "length": r["length"],
                       "pointer": json.loads(r["pointer"]) if r["pointer"] else None}
    return out


def hf_find_cve(cve: str, limit: int = 20) -> dict:
    """Записи датасета, где упоминается CVE (например "CVE-2023-44487"): разборы, CVSS, CWE, рекомендации."""
    _require_index()
    m = R.CVE_RE.search(cve)
    if not m:
        raise ToolError("Ожидается идентификатор вида CVE-2024-12345")
    c = m.group(0).upper()
    rows = db().execute("SELECT d.* FROM cves x JOIN docs d ON d.id=x.doc_id WHERE x.cve=? "
                        "ORDER BY instr(upper(d.title), ?)=0, length(d.title) LIMIT ?",
                        (c, c, max(1, min(limit, 100)))).fetchall()
    return {"cve": c, "results": [_doc_summary(r) for r in rows]}


def hf_overview() -> dict:
    """Структура датасета: темы (category) с числом записей в индексе и файлов; покрытие индекса."""
    files = C.list_files()
    total = {}
    for f in files:
        c = C.category_of(f["path"])
        t = total.setdefault(c, [0, 0])
        t[0] += 1
        t[1] += f["size"]
    out = {"repo": C.REPO, "files": len(files), "size_gb": round(sum(f["size"] for f in files) / 1e9, 1)}
    if os.path.exists(DB):
        con = db()
        idx = {r[0]: (r[1], r[2]) for r in con.execute(
            "SELECT category, count(*), sum(records) FROM files GROUP BY category")}
        out["indexed_files"], out["indexed_records"], out["indexed_gb"] = con.execute(
            "SELECT count(*), sum(records), round(sum(size)/1e9, 2) FROM files").fetchone()
        out["categories"] = sorted(
            [{"category": c, "files": n, "size_mb": round(s / 1e6, 1), "indexed_files": idx.get(c, (0, 0))[0],
              "indexed_records": idx.get(c, (0, 0))[1] or 0} for c, (n, s) in total.items()],
            key=lambda x: -x["indexed_records"])
        out["largest_indexed"] = [dict(r) for r in con.execute(
            "SELECT path, records, round(size/1e6,1) AS size_mb FROM files ORDER BY records DESC LIMIT 12")]
    else:
        out["index"] = "не собран"
        out["categories"] = [{"category": c, "files": n, "size_mb": round(s / 1e6, 1)} for c, (n, s) in total.items()]
    out["note"] = ("category=vulnerability-intelligence в корне — в основном архивы исходников ARVO (repo-vul/repo-fix "
                   ".tar.gz), в индекс попадают только их описания")
    return out


def hf_list_files(pattern: str | None = None, category: str | None = None, include_archives: bool = False,
                  include_duplicates: bool = False, limit: int = 100) -> dict:
    """Файлы датасета (путь, размер, тема, в индексе ли).

    pattern: регулярное выражение по пути ("mitre", "nvd-realtime", "\\.jsonl$").
    include_archives: показывать .tar.gz ARVO (исходники уязвимых/исправленных проектов).
    include_duplicates: показывать копии (в датасете много дублей в корне и с суффиксом __dupN).
    """
    files = C.list_files()
    if not include_duplicates:
        files = C.dedupe([f for f in files if "__dup" not in f["path"]])
    if not include_archives:
        files = [f for f in files if not C.is_archive(f["path"])]
    if category:
        files = [f for f in files if C.category_of(f["path"]) == category]
    if pattern:
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            raise ToolError(f"Неверное регулярное выражение: {e}")
        files = [f for f in files if rx.search(f["path"])]
    indexed = set()
    if os.path.exists(DB):
        indexed = {r[0] for r in db().execute("SELECT path FROM files")}
    files.sort(key=lambda f: -f["size"])
    lim = max(1, min(limit, 500))
    return {"total": len(files), "files": [
        {"path": f["path"], "size_mb": round(f["size"] / 1e6, 3), "category": C.category_of(f["path"]),
         "indexed": f["path"] in indexed} for f in files[:lim]]}


def hf_read_file(path: str, offset: int = 0, length: int = 20000) -> dict:
    """Прочитать кусок файла датасета по байтам (Range-запрос), без скачивания файла целиком.

    length: до 200000 байт. Для JSONL удобно сначала найти строку через hf_grep_file (он возвращает offset).
    """
    f = _known_file(path)
    if C.is_archive(path):
        raise ToolError("Это архив; читать можно только текстовые файлы")
    offset = max(0, offset)
    length = max(1, min(length, 200000))
    data = C.read_range(path, offset, length)
    return {"path": path, "size": f["size"], "offset": offset, "length": len(data),
            "next_offset": offset + len(data) if offset + len(data) < f["size"] else None,
            "text": data.decode("utf-8", "replace")}


def hf_grep_file(path: str, regex: str, ignore_case: bool = True, max_hits: int = 20, max_mb: int = 300,
                 start_offset: int = 0, context_chars: int = 400) -> dict:
    """Потоковый поиск регулярного выражения по строкам файла датасета (без скачивания на диск).

    Подходит для файлов вне индекса и для точных шаблонов ("CWE-79", "kubectl .*--privileged").
    max_mb: сколько мегабайт просмотреть максимум (до 3000); start_offset: продолжить с байта
    (next_offset из прошлого ответа). Возвращает строки с номером, смещением и фрагментом вокруг совпадения.
    """
    f = _known_file(path)
    if C.is_archive(path):
        raise ToolError("Это архив; grep работает по текстовым файлам")
    try:
        rx = re.compile(regex.encode(), re.I if ignore_case else 0)
    except re.error as e:
        raise ToolError(f"Неверное регулярное выражение: {e}")
    budget = max(1, min(max_mb, 3000)) * 1_000_000
    max_hits = max(1, min(max_hits, 200))
    ctx = max(50, min(context_chars, 4000))
    hits, off, n_lines, t0 = [], max(0, start_offset), 0, time.time()
    stream = C.open_stream(path, off)
    if off:
        off += len(stream.readline())  # дочитать до начала следующей строки
    stopped = None
    for line in stream:
        n_lines += 1
        m = rx.search(line)
        if m:
            s = max(0, m.start() - ctx // 4)
            hits.append({"offset": off, "length": len(line), "match": m.group(0).decode("utf-8", "replace")[:200],
                         "context": line[s:s + ctx].decode("utf-8", "replace").strip()})
        off += len(line)
        if len(hits) >= max_hits:
            stopped = "max_hits"
            break
        if off - start_offset >= budget:
            stopped = "max_mb"
            break
        if time.time() - t0 > 90:
            stopped = "timeout"
            break
    stream.close()
    return {"path": path, "size": f["size"], "scanned_bytes": off - start_offset, "lines": n_lines,
            "stopped": stopped, "next_offset": off if stopped and off < f["size"] else None, "hits": hits}


TOOLS = [hf_search, hf_get_record, hf_find_cve, hf_overview, hf_list_files, hf_read_file, hf_grep_file]


class HfCyberSource(Source):
    name = "hf"
    title = f"Hugging Face: {C.REPO}"
    instructions = INSTRUCTIONS
    get_tool = "hf_get_record(id=…)"

    def available(self):
        if not C.token():
            return False, "нет HF_TOKEN (переменная окружения или .env в корне)"
        return True, ""

    def register(self, mcp):
        for fn in TOOLS:
            mcp.tool(annotations=RO_REMOTE)(fn)

    def stats(self):
        if not os.path.exists(DB):
            return {"index": "не собран"}
        files, recs, gb = db().execute("SELECT count(*), sum(records), round(sum(size)/1e9,2) FROM files").fetchone()
        return {"indexed_files": files, "indexed_records": recs, "indexed_gb": gb}

    def search(self, query, limit=5):
        if not os.path.exists(DB):
            return []
        _, rows = _search_rows(db(), query, limit=limit)
        loaded = _load_many(rows)
        return [{**_doc_summary(r), "snippet": snippet_of(t, query, 240)} for r, (_, t) in zip(rows, loaded)]
