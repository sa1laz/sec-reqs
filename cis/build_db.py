#!/usr/bin/env python3
"""Сборка SQLite-базы для MCP-сервера из cis/benchmarks/*.

  .venv/bin/python cis/build_db.py            # → cis/cis.db

Таблицы:
  benchmarks   — один бенчмарк на строку, с определениями профилей и описанием технологии
  sections     — дерево разделов
  recs         — рекомендации (все поля из recommendations.jsonl)
  rec_profiles — профиль ↔ рекомендация
  rec_controls — привязка к CIS Controls
  recs_fts     — полнотекстовый индекс (FTS5, bm25) по названию, описанию, аудиту, исправлению
"""
import glob, json, os, re, sqlite3, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "cis.db")

SCHEMA = """
CREATE TABLE benchmarks(
  id INTEGER PRIMARY KEY, slug TEXT UNIQUE, title TEXT, version TEXT, published TEXT,
  community TEXT, collection TEXT, is_stig INTEGER, pages INTEGER,
  n_recs INTEGER, n_automated INTEGER, n_manual INTEGER,
  overview TEXT, target_technology TEXT, profile_definitions TEXT, source_url TEXT, title_norm TEXT);
CREATE TABLE sections(
  benchmark_id INTEGER, number TEXT, title TEXT, level INTEGER, description TEXT, sort_key TEXT,
  PRIMARY KEY(benchmark_id, number));
CREATE TABLE recs(
  rowid INTEGER PRIMARY KEY, uid TEXT UNIQUE, benchmark_id INTEGER, rec_id TEXT, title TEXT,
  assessment_status TEXT, profiles TEXT, section_path TEXT, section TEXT,
  description TEXT, rationale TEXT, impact TEXT, audit TEXT, remediation TEXT, default_value TEXT,
  additional_information TEXT, refs TEXT, cis_controls TEXT, mitre_attack TEXT,
  page_start INTEGER, page_end INTEGER, sort_key TEXT, duplicate_number_in_source INTEGER);
CREATE INDEX recs_bm ON recs(benchmark_id, sort_key);
CREATE INDEX recs_bm_id ON recs(benchmark_id, rec_id);
CREATE TABLE rec_profiles(uid TEXT, benchmark_id INTEGER, profile TEXT);
CREATE INDEX rp ON rec_profiles(benchmark_id, profile);
CREATE TABLE rec_controls(uid TEXT, benchmark_id INTEGER, version TEXT, control TEXT, title TEXT,
  ig1 INTEGER, ig2 INTEGER, ig3 INTEGER);
CREATE INDEX rc ON rec_controls(version, control);
CREATE VIRTUAL TABLE recs_fts USING fts5(
  title, benchmark, description, rationale, audit, remediation,
  content='', tokenize='porter unicode61 remove_diacritics 2');
"""


def sort_key(num):
    """'4.10.2' → '0004.0010.0002' для правильной сортировки."""
    return ".".join(f"{int(p):04d}" if p.isdigit() else p for p in num.split("."))


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def main():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    rowid = 0
    for d in sorted(glob.glob(os.path.join(HERE, "benchmarks", "*", ""))):
        m = json.load(open(d + "benchmark.json"))
        recs = [json.loads(l) for l in open(d + "recommendations.jsonl")]
        fm = m.get("front_matter") or {}
        bid = m["workbench_id"]
        con.execute("INSERT INTO benchmarks VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            bid, m["slug"], m["title"], m["version"], m["published"], m.get("community"), m.get("collection"),
            int("STIG" in m["title"]), m["pages"], len(recs), m["counts"]["automated"], m["counts"]["manual"],
            fm.get("overview"), fm.get("target_technology_details"), fm.get("profile_definitions"),
            m["source_url"], norm(m["title"])))
        for s in m["sections"]:
            con.execute("INSERT OR IGNORE INTO sections VALUES(?,?,?,?,?,?)",
                        (bid, s["number"], s["title"], s["level"], s["description"], sort_key(s["number"])))
        for r in recs:
            rowid += 1
            path = r["section_path"]
            con.execute("INSERT INTO recs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                rowid, r["uid"], bid, r["id"], r["title"], r["assessment_status"],
                json.dumps(r["profiles"], ensure_ascii=False), json.dumps(path, ensure_ascii=False),
                " > ".join(f'{p["number"]} {p["title"]}' for p in path),
                r["description"], r["rationale"], r["impact"], r["audit"], r["remediation"], r["default_value"],
                r["additional_information"], json.dumps(r["references"], ensure_ascii=False),
                json.dumps(r["cis_controls"], ensure_ascii=False), r["mitre_attack"],
                r["page_start"], r["page_end"], sort_key(r["id"]), int(bool(r.get("duplicate_number_in_source")))))
            con.executemany("INSERT INTO rec_profiles VALUES(?,?,?)", [(r["uid"], bid, p) for p in r["profiles"]])
            con.executemany("INSERT INTO rec_controls VALUES(?,?,?,?,?,?,?,?)", [
                (r["uid"], bid, c["version"], c["control"], c["title"], int(c["ig1"]), int(c["ig2"]), int(c["ig3"]))
                for c in r["cis_controls"] if c.get("control")])
            con.execute("INSERT INTO recs_fts(rowid,title,benchmark,description,rationale,audit,remediation) VALUES(?,?,?,?,?,?,?)",
                        (rowid, r["title"], m["title"], r["description"] or "", r["rationale"] or "",
                         r["audit"] or "", r["remediation"] or ""))
    con.execute("INSERT INTO recs_fts(recs_fts) VALUES('optimize')")
    con.commit()
    con.execute("VACUUM")
    n_b, n_r = con.execute("SELECT (SELECT count(*) FROM benchmarks),(SELECT count(*) FROM recs)").fetchone()
    con.close()
    print(f"{DB}: {n_b} бенчмарков, {n_r} рекомендаций, {os.path.getsize(DB)/1e6:.0f} МБ")


if __name__ == "__main__":
    sys.exit(main())
