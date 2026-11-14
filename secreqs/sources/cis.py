"""Источник cis: локальная база CIS Benchmarks (cis/cis.db, собирается cis/build_db.py)."""
from __future__ import annotations

import json
import os
import re
from typing import Literal

from mcp.server.mcpserver.exceptions import ToolError

from secreqs.core import RO, ROOT, Source, fts_query, ro_db, snippet_of

DB = os.environ.get("CIS_DB", os.path.join(ROOT, "cis", "cis.db"))

INSTRUCTIONS = """\
Локальная база CIS Benchmarks: последние опубликованные версии (срез WorkBench 2026-11-14), ~350 бенчмарков,
~42 тыс. рекомендаций с описанием, обоснованием, аудитом (команды), исправлением, значением по умолчанию,
профилями (Level 1/2) и привязкой к CIS Controls v8/v7.
1. cis_search_benchmarks — найти бенчмарк под технологию («EKS», «Ubuntu 24.04», «PostgreSQL 16»).
   Почти у каждого продукта есть обычный бенчмарк и вариант «STIG»; если STIG не просили, бери обычный.
2. cis_get_benchmark — профили и разделы.
3. Поиск пробелов: cis_list_recommendations с include=["audit"] → сверить конфигурацию → cis_get_recommendation
   для отклонений (исправление, значение по умолчанию).
4. cis_search_recommendations — полнотекстовый поиск; cis_find_by_control — покрытие CIS Control (v8 13.4).
Ссылайся как «CIS <бенчмарк> v<версия>, <номер> <название>». Текст CIS — CC BY-NC-SA 4.0, только для
внутреннего использования, не публиковать.
"""

SUMMARY = ["uid", "benchmark_id", "rec_id", "title", "assessment_status", "profiles", "section"]
TEXT_FIELDS = ["description", "rationale", "impact", "audit", "remediation", "default_value",
               "additional_information", "references", "cis_controls", "mitre_attack"]
ALIASES = {"aws": "amazon web services", "gcp": "google cloud platform", "k8s": "kubernetes",
           "rhel": "red hat enterprise linux", "win": "windows", "m365": "microsoft 365", "o365": "microsoft 365",
           "gws": "google workspace", "mssql": "sql server", "postgres": "postgresql", "osx": "macos"}


def db():
    return ro_db(DB)


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def title_words(ref):
    """Слова для поиска по названию: без «CIS»/«Benchmark», с раскрытием сокращений."""
    words = []
    for w in norm(re.sub(r"(?i)\bcis\b|\bbenchmarks?\b", " ", ref)).split():
        words += ALIASES.get(w, w).split()
    return words


def like_args(words):
    return [f"% {w} %" if len(w) <= 3 else f"%{w}%" for w in words]


def resolve_benchmark(con, ref):
    """ID WorkBench, slug или часть названия → строка benchmarks. Ошибка со списком кандидатов при неоднозначности."""
    ref = str(ref).strip()
    if ref.isdigit():
        row = con.execute("SELECT * FROM benchmarks WHERE id=?", (int(ref),)).fetchone()
        if row:
            return row
    row = con.execute("SELECT * FROM benchmarks WHERE slug=?", (ref,)).fetchone()
    if row:
        return row
    words = title_words(ref)
    if not words:
        raise ToolError("Пустая ссылка на бенчмарк")
    where = " AND ".join(["(' ' || title_norm || ' ') LIKE ?"] * len(words))
    rows = con.execute(f"SELECT * FROM benchmarks WHERE {where} ORDER BY is_stig, length(title)",
                       like_args(words)).fetchall()
    if len(rows) == 1:
        return rows[0]
    if not rows:
        raise ToolError(f"Бенчмарк «{ref}» не найден. Используй cis_search_benchmarks.")
    exact = [r for r in rows if norm(r["title"]) in (norm(ref), norm("CIS " + ref), norm("CIS " + ref + " Benchmark"))]
    if len(exact) == 1:
        return exact[0]
    cands = "; ".join(f'{r["id"]}: {r["title"]} v{r["version"]}' for r in rows[:15])
    raise ToolError(f"Неоднозначно, подходит {len(rows)} бенчмарков: {cands}. Укажи ID.")


def rec_dict(row, fields):
    out = {}
    for f in fields:
        if f in ("profiles", "section_path", "cis_controls"):
            out[f] = json.loads(row[f])
        elif f == "references":
            out[f] = json.loads(row["refs"])
        elif f == "rec_id":
            out["id"] = row["rec_id"]
        else:
            out[f] = row[f]
    return out


def rec_snippet(row, q, width=220):
    words = [w.lower() for w in re.findall(r"\w{3,}", q)]
    for f in ("description", "audit", "remediation", "rationale"):
        t = row[f] or ""
        if any(w in t.lower() for w in words):
            return f"[{f}] " + snippet_of(t, q, width)
    return re.sub(r"\s+", " ", (row["description"] or "")[:width])


# ---------------------------------------------------------------- инструменты

def cis_search_benchmarks(query: str = "", collection: str | None = None, include_stig: bool = True,
                          limit: int = 50) -> dict:
    """Найти CIS-бенчмарки по названию технологии.

    query: слова из названия, например "kubernetes", "windows server 2022", "aws". Пусто — весь список.
    collection: фильтр по коллекции WorkBench ("Operating System", "Database Server", "STIG", …).
    include_stig: включать ли варианты DISA STIG.
    Возвращает ID, название, версию, дату публикации и число рекомендаций.
    """
    con = db()
    sql, args = "SELECT * FROM benchmarks WHERE 1=1", []
    for a in like_args(title_words(query)):
        sql += " AND (' ' || title_norm || ' ') LIKE ?"
        args.append(a)
    if collection:
        sql += " AND collection LIKE ?"
        args.append(f"%{collection}%")
    if not include_stig:
        sql += " AND is_stig=0"
    rows = con.execute(sql + " ORDER BY is_stig, title LIMIT ?", args + [max(1, min(limit, 400))]).fetchall()
    total = con.execute(sql.replace("SELECT *", "SELECT count(*)"), args).fetchone()[0]
    return {"total": total, "benchmarks": [
        {"id": r["id"], "title": r["title"], "version": r["version"], "published": r["published"],
         "collection": r["collection"], "recommendations": r["n_recs"], "stig": bool(r["is_stig"])} for r in rows]}


def cis_get_benchmark(benchmark: str, include_overview: bool = False) -> dict:
    """Метаданные CIS-бенчмарка: версия, дата, профили, дерево разделов с числом рекомендаций.

    benchmark: ID WorkBench (например "27155"), slug или однозначная часть названия ("EKS Auto Mode").
    include_overview: добавить вводный текст и описание целевой технологии.
    """
    con = db()
    b = resolve_benchmark(con, benchmark)
    counts = {}
    for (sec,) in con.execute("SELECT section_path FROM recs WHERE benchmark_id=?", (b["id"],)):
        for p in json.loads(sec):
            counts[p["number"]] = counts.get(p["number"], 0) + 1
    profiles = [r[0] for r in con.execute(
        "SELECT profile FROM rec_profiles WHERE benchmark_id=? GROUP BY profile ORDER BY count(*) DESC", (b["id"],))]
    out = {
        "id": b["id"], "title": b["title"], "version": b["version"], "published": b["published"],
        "collection": b["collection"], "source_url": b["source_url"], "recommendations": b["n_recs"],
        "automated": b["n_automated"], "manual": b["n_manual"], "profiles": profiles,
        "profile_definitions": b["profile_definitions"],
        "sections": [{"number": s["number"], "title": s["title"], "recommendations": counts.get(s["number"], 0)}
                     for s in con.execute("SELECT * FROM sections WHERE benchmark_id=? ORDER BY sort_key", (b["id"],))],
    }
    if include_overview:
        out["overview"] = b["overview"]
        out["target_technology"] = b["target_technology"]
    return out


def _search(con, query, benchmark=None, profile=None, assessment_status=None, include_stig=False, limit=20):
    q = fts_query(query)
    if not q:
        raise ToolError("Пустой запрос")
    sql = ("SELECT r.*, b.title AS btitle, b.version AS bversion FROM recs_fts f "
           "JOIN recs r ON r.rowid=f.rowid JOIN benchmarks b ON b.id=r.benchmark_id WHERE recs_fts MATCH ?")
    args = [q]
    if benchmark:
        sql += " AND r.benchmark_id=?"
        args.append(resolve_benchmark(con, benchmark)["id"])
    elif not include_stig:
        sql += " AND b.is_stig=0"
    if profile:
        sql += " AND r.profiles LIKE ?"
        args.append(f"%{profile}%")
    if assessment_status:
        sql += " AND r.assessment_status=?"
        args.append(assessment_status)
    sql += " ORDER BY bm25(recs_fts, 10.0, 2.0, 3.0, 1.0, 2.0, 1.5) LIMIT ?"
    return q, con.execute(sql, args + [max(1, min(limit, 100))]).fetchall()


def cis_search_recommendations(query: str, benchmark: str | None = None, profile: str | None = None,
                               assessment_status: Literal["Automated", "Manual"] | None = None,
                               include_stig: bool = False, limit: int = 20) -> dict:
    """Полнотекстовый поиск CIS-рекомендаций (название, описание, обоснование, аудит, исправление).

    query: слова или "фраза в кавычках", например "network policy", "sshd PermitRootLogin", "MFA root account".
    benchmark: ограничить одним бенчмарком (ID, slug или часть названия).
    profile: подстрока профиля, например "Level 1".
    include_stig: при поиске по всей базе включать STIG-варианты (по умолчанию нет, чтобы не дублировать).
    Возвращает uid, бенчмарк, номер, название, статус, профили и фрагмент текста с совпадением.
    """
    q, rows = _search(db(), query, benchmark, profile, assessment_status, include_stig, limit)
    return {"query": q, "results": [
        {"uid": r["uid"], "benchmark": f'{r["btitle"]} v{r["bversion"]}', "benchmark_id": r["benchmark_id"],
         "id": r["rec_id"], "title": r["title"], "assessment_status": r["assessment_status"],
         "profiles": json.loads(r["profiles"]), "section": r["section"], "snippet": rec_snippet(r, query)}
        for r in rows]}


def cis_get_recommendation(uid: str | None = None, benchmark: str | None = None, id: str | None = None,
                           fields: list[str] | None = None) -> dict:
    """Полная CIS-рекомендация: описание, обоснование, влияние, аудит, исправление, значение по умолчанию,
    ссылки, CIS Controls, MITRE ATT&CK.

    Укажи uid (например "cis:27155:4.3.1") или пару benchmark + id ("EKS Auto Mode", "4.3.1").
    fields: вернуть только эти поля из: description, rationale, impact, audit, remediation, default_value,
    additional_information, references, cis_controls, mitre_attack.
    """
    con = db()
    if uid:
        row = con.execute("SELECT * FROM recs WHERE uid=?", (uid,)).fetchone()
    elif benchmark and id:
        b = resolve_benchmark(con, benchmark)
        row = con.execute("SELECT * FROM recs WHERE benchmark_id=? AND rec_id=? ORDER BY uid", (b["id"], id)).fetchone()
    else:
        raise ToolError("Нужен uid или benchmark + id")
    if not row:
        raise ToolError("Рекомендация не найдена")
    b = con.execute("SELECT title, version, source_url FROM benchmarks WHERE id=?", (row["benchmark_id"],)).fetchone()
    want = [f for f in (fields or TEXT_FIELDS) if f in TEXT_FIELDS]
    out = rec_dict(row, SUMMARY + ["section_path", "page_start", "page_end"] + want)
    out.pop("section", None)
    out["benchmark"] = f'{b["title"]} v{b["version"]}'
    out["source_url"] = b["source_url"]
    return out


def cis_list_recommendations(benchmark: str, section: str | None = None, profile: str | None = None,
                             assessment_status: Literal["Automated", "Manual"] | None = None,
                             include: list[str] | None = None, offset: int = 0, limit: int = 100) -> dict:
    """Список рекомендаций CIS-бенчмарка по порядку — основа для чек-листа и поиска пробелов.

    section: номер раздела, включая вложенные ("4" или "4.3").
    profile: подстрока профиля ("Level 1", "Level 2 - Worker Node").
    include: добавить текстовые поля к каждой записи, например ["audit"] для сверки конфигурации
    или ["audit", "default_value"]. Без include возвращаются только номер, название, статус и профили.
    offset/limit: постраничный вывод (limit до 200; с include — до 50).
    """
    con = db()
    b = resolve_benchmark(con, benchmark)
    sql, args = "SELECT * FROM recs WHERE benchmark_id=?", [b["id"]]
    if section:
        sql += " AND (rec_id=? OR rec_id LIKE ?)"
        args += [section, section.rstrip(".") + ".%"]
    if profile:
        sql += " AND profiles LIKE ?"
        args.append(f"%{profile}%")
    if assessment_status:
        sql += " AND assessment_status=?"
        args.append(assessment_status)
    total = con.execute(sql.replace("SELECT *", "SELECT count(*)"), args).fetchone()[0]
    extra = [f for f in (include or []) if f in TEXT_FIELDS]
    cap = 50 if extra else 200
    rows = con.execute(sql + " ORDER BY sort_key, uid LIMIT ? OFFSET ?",
                       args + [max(1, min(limit, cap)), max(0, offset)]).fetchall()
    items = []
    for r in rows:
        d = rec_dict(r, SUMMARY + extra)
        d.pop("benchmark_id")
        items.append(d)
    nxt = offset + len(rows)
    return {"benchmark": f'{b["title"]} v{b["version"]}', "benchmark_id": b["id"], "total": total,
            "offset": offset, "next_offset": nxt if nxt < total else None, "recommendations": items}


def cis_find_by_control(control: str, version: Literal["v8", "v7"] = "v8", benchmark: str | None = None,
                        implementation_group: Literal[1, 2, 3] | None = None, include_stig: bool = False,
                        limit: int = 100) -> dict:
    """CIS-рекомендации, сопоставленные с CIS Control (например "13.4" или "6" для всего контроля).

    implementation_group: только рекомендации, отмеченные для IG1/IG2/IG3.
    benchmark: ограничить одним бенчмарком; без него — по всей базе.
    """
    con = db()
    sql = ("SELECT c.title AS ctitle, r.uid, r.rec_id, r.title, r.assessment_status, b.id AS bid, b.title AS btitle, "
           "b.version AS bversion FROM rec_controls c JOIN recs r ON r.uid=c.uid JOIN benchmarks b ON b.id=c.benchmark_id "
           "WHERE c.version=? AND (c.control=? OR c.control LIKE ?)")
    args = [version, control, control.rstrip(".") + ".%"]
    if benchmark:
        sql += " AND c.benchmark_id=?"
        args.append(resolve_benchmark(con, benchmark)["id"])
    elif not include_stig:
        sql += " AND b.is_stig=0"
    if implementation_group:
        sql += f" AND c.ig{int(implementation_group)}=1"
    total = con.execute(f"SELECT count(*) FROM ({sql})", args).fetchone()[0]
    per_bm = {r[0]: r[1] for r in con.execute(f"SELECT bid, count(*) FROM ({sql}) GROUP BY bid", args)}
    rows = con.execute(sql + " ORDER BY b.is_stig, b.title, r.sort_key LIMIT ?", args + [max(1, min(limit, 300))]).fetchall()
    titles = sorted({r["ctitle"] for r in rows if r["ctitle"]})
    return {"control": f"{version} {control}", "control_titles": titles, "total": total,
            "benchmarks_covering": len(per_bm),
            "results": [{"uid": r["uid"], "benchmark": f'{r["btitle"]} v{r["bversion"]}', "id": r["rec_id"],
                         "title": r["title"], "assessment_status": r["assessment_status"]} for r in rows]}


TOOLS = [cis_search_benchmarks, cis_get_benchmark, cis_search_recommendations, cis_get_recommendation,
         cis_list_recommendations, cis_find_by_control]


class CisSource(Source):
    name = "cis"
    title = "CIS Benchmarks"
    instructions = INSTRUCTIONS
    get_tool = "cis_get_recommendation(uid=…)"

    def available(self):
        if not os.path.exists(DB):
            return False, f"нет базы {DB}; собрать: .venv/bin/python cis/build_db.py"
        return True, ""

    def register(self, mcp):
        for fn in TOOLS:
            mcp.tool(annotations=RO)(fn)

    def stats(self):
        n_b, n_r = db().execute("SELECT (SELECT count(*) FROM benchmarks), (SELECT count(*) FROM recs)").fetchone()
        return {"benchmarks": n_b, "recommendations": n_r, "license": "CC BY-NC-SA 4.0 (internal use only)"}

    def search(self, query, limit=5):
        _, rows = _search(db(), query, limit=limit)
        return [{"id": r["uid"], "title": f'{r["rec_id"]} {r["title"]}', "where": f'{r["btitle"]} v{r["bversion"]}',
                 "snippet": rec_snippet(r, query)} for r in rows]
