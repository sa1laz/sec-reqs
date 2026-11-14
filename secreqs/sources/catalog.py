"""Источник req: единый каталог требований из открытых стандартов (data/catalog.db, secreqs.catalog.build)
и связи между ними (crosswalk). CIS живёт отдельно (cis_*), но связи через CIS Controls учитываются."""
from __future__ import annotations

import json
import os
import re
import sqlite3

from mcp.server.mcpserver.exceptions import ToolError

from secreqs.catalog.build import DB
from secreqs.catalog.model import NS, norm_ref
from secreqs.core import RO, Source, fts_query, fts_query_or, read_status, ro_db, snippet_of

INSTRUCTIONS = """\
Каталог требований из открытых стандартов в одном формате «стандарт → документ → элемент» со связями между ними:
DISA STIG/SRG (+CCI), CISA SCuBA (Google Workspace, M365), NIST SP 800-53 rev5 (+базовые наборы), CSF 2.0, SSDF,
800-171, AI RMF и другие — полный список и даты срезов в req_frameworks.
0. Состав: STIG, SCuBA, NIST (800-53, CSF 2.0, SSDF, 800-171, AI RMF), ComplianceAsCode (правила Linux/OpenShift/EKS
   со связями на CIS/STIG/NIST/PCI/HIPAA/ISO), Prowler (проверки облаков и SaaS + сопоставления с ISO 27001, PCI DSS,
   SOC 2, NIS2, C5, HIPAA, GDPR…), Kubernetes PSS и политики Kyverno, OWASP ASVS/MASVS/LLM Top 10, MITRE ATT&CK,
   ATLAS, D3FEND, CWE, CAPEC, CISA KEV + EPSS (req_cve).
1. req_frameworks → req_documents(framework, query) — найти документ (например, STIG для «kubernetes»).
2. req_search — полнотекстовый поиск по всем стандартам или внутри одного; фильтры severity/kind.
3. req_list(framework, document) с include=["check","fix"] — чек-лист для сверки конфигурации.
4. req_get(uid) — элемент целиком. uid = <framework>:<document>:<id>, например stig:RHEL_9_STIG:V-257777,
   nist-800-53:catalog:AC-2(1), scuba:gws-gmail:GWS.GMAIL.2.1v1.
5. req_related — связи: что элемент реализует (STIG → CCI → NIST 800-53, SCuBA → 800-53/ATT&CK) и что ещё в других
   стандартах связано с тем же требованием. Можно спросить по идентификатору: ns="nist-800-53", id="AC-2".
Пространства имён идентификаторов: nist-800-53, nist-csf-2, nist-ssdf, cci, srg, stig (V-id), stig-id, attack, cwe,
capec, cve, cis-controls-v8 и другие (req_frameworks → namespaces).
"""

TEXT_ORDER = ["description", "rationale", "check", "fix", "guidance", "default", "note", "examples", "overview",
              "assessment_objective", "assessment_method"]


def db():
    return ro_db(DB)


def _fts(con, query, where="", args=(), limit=20):
    q = fts_query(query)
    if not q:
        raise ToolError("Пустой запрос")
    for qq in (q, fts_query_or(query)):
        rows = con.execute(
            "SELECT i.* FROM items_fts f JOIN items i ON i.rowid=f.rowid WHERE items_fts MATCH ?" + where +
            " ORDER BY bm25(items_fts, 8.0, 1.0) LIMIT ?", (qq, *args, limit)).fetchall()
        if rows or qq == fts_query_or(query):
            return qq, rows
    return q, []


def _dedupe(rows, limit, keep_compliance=False):
    """Убрать повторы: одно требование встречается во многих файлах соответствия Prowler (по версиям и
    провайдерам) и в разных STIG. Одинаковые названия схлопываются, копии из prowler-compliance — не больше трети."""
    out, seen, n_pc = [], set(), 0
    cap = limit if keep_compliance else max(1, limit // 3)
    for r in rows:
        key = re.sub(r"\W+", " ", (r["title"] or "").lower()).strip()
        if key in seen:
            continue
        if r["framework"] == "prowler-compliance":
            if n_pc >= cap:
                continue
            n_pc += 1
        seen.add(key)
        out.append(r)
        if len(out) >= limit:
            break
    return out


def _summary(r, query=None) -> dict:
    d = {"uid": r["uid"], "framework": r["framework"], "document": r["document"], "id": r["item_id"],
         "title": r["title"], "kind": r["kind"]}
    if r["severity"]:
        d["severity"] = r["severity"]
    if r["parent"]:
        d["parent"] = r["parent"]
    prof = json.loads(r["profiles"])
    if prof:
        d["profiles"] = prof
    if query:
        text = json.loads(r["text"])
        for f in TEXT_ORDER + list(text):
            t = text.get(f)
            if t and any(w.lower() in t.lower() for w in re.findall(r"\w{3,}", query)):
                d["snippet"] = f"[{f}] " + snippet_of(t, query, 260)
                break
    return d


def _doc_title(con, fw, doc):
    r = con.execute("SELECT title, version FROM documents WHERE framework=? AND id=?", (fw, doc)).fetchone()
    return f'{r["title"]}' + (f' {r["version"]}' if r and r["version"] else "") if r else doc


def _resolve_doc(con, framework, document):
    if not document:
        return None
    r = con.execute("SELECT id FROM documents WHERE framework=? AND id=?", (framework, document)).fetchone()
    if r:
        return r["id"]
    words = re.sub(r"[^a-z0-9]+", " ", document.lower()).split()
    sql = "SELECT id, title, version FROM documents WHERE framework=?" + " AND (' '||title_norm||' '||lower(id)) LIKE ?" * len(words)
    rows = con.execute(sql, (framework, *[f"%{w}%" for w in words])).fetchall()
    if len(rows) == 1:
        return rows[0]["id"]
    if not rows:
        raise ToolError(f"Документ «{document}» не найден в {framework}. Используй req_documents.")
    raise ToolError("Неоднозначно: " + "; ".join(f'{r["id"]} ({r["title"]} {r["version"] or ""})' for r in rows[:15]))


# ---------------------------------------------------------------- инструменты

def req_frameworks() -> dict:
    """Стандарты в каталоге: id, название, версия/дата среза, тип (benchmark/controls/threats/…), лицензия,
    число документов и элементов. Плюс пространства имён идентификаторов для req_related."""
    con = db()
    return {"frameworks": [{k: r[k] for k in ("id", "title", "version", "published", "kind", "publisher", "license",
                                              "n_documents", "n_items", "url")}
                           for r in con.execute("SELECT * FROM frameworks ORDER BY kind, id")],
            "namespaces": NS}


def req_documents(framework: str, query: str = "", limit: int = 50) -> dict:
    """Документы стандарта (отдельные STIG/SRG, продукты SCuBA, …) с поиском по названию.

    framework: id из req_frameworks ("stig", "scuba", …). query: слова из названия ("kubernetes", "windows 2022").
    """
    con = db()
    words = re.sub(r"[^a-z0-9]+", " ", query.lower()).split()
    sql = "SELECT * FROM documents WHERE framework=?" + " AND (' '||title_norm||' '||lower(id)) LIKE ?" * len(words)
    args = [framework, *[f"%{w}%" for w in words]]
    total = con.execute(sql.replace("SELECT *", "SELECT count(*)"), args).fetchone()[0]
    rows = con.execute(sql + " ORDER BY title LIMIT ?", args + [max(1, min(limit, 500))]).fetchall()
    return {"framework": framework, "total": total, "documents": [
        {"id": r["id"], "title": r["title"], "version": r["version"], "date": r["date"], "items": r["n_items"],
         **({"type": json.loads(r["extra"]).get("type")} if json.loads(r["extra"]).get("type") else {})} for r in rows]}


def req_search(query: str, framework: str | None = None, document: str | None = None, severity: str | None = None,
               kind: str | None = None, limit: int = 20) -> dict:
    """Полнотекстовый поиск требований по всем стандартам каталога или внутри одного.

    query: слова или "фраза" ("audit log retention", "PermitRootLogin", "phishing-resistant MFA").
    framework: id стандарта; document: id или часть названия документа (нужен framework).
    severity: подстрока ("CAT I", "SHALL", "high"); kind: тип элемента ("rule", "policy", "subcategory", …).
    """
    con = db()
    where, args = "", []
    if framework:
        where += " AND i.framework=?"
        args.append(framework)
        if document:
            where += " AND i.document=?"
            args.append(_resolve_doc(con, framework, document))
    if severity:
        where += " AND i.severity LIKE ?"
        args.append(f"%{severity}%")
    if kind:
        where += " AND i.kind=?"
        args.append(kind)
    lim = max(1, min(limit, 100))
    q, rows = _fts(con, query, where, args, lim * 5)
    rows = _dedupe(rows, lim, keep_compliance=framework == "prowler-compliance")
    out = []
    for r in rows:
        d = _summary(r, query)
        d["document_title"] = _doc_title(con, r["framework"], r["document"])
        out.append(d)
    return {"query": q, "match": "all" if q == fts_query(query) else "any", "results": out}


def req_get(uid: str, fields: list[str] | None = None) -> dict:
    """Элемент каталога целиком: тексты (описание, обоснование, проверка, исправление, руководство…), ссылки,
    связи с другими стандартами. uid из результатов поиска; fields — только эти текстовые поля."""
    con = db()
    r = con.execute("SELECT * FROM items WHERE uid=?", (uid,)).fetchone()
    if not r:
        raise ToolError(f"Нет элемента {uid}")
    text = json.loads(r["text"])
    if fields:
        text = {k: v for k, v in text.items() if k in fields}
    out = _summary(r)
    out["document_title"] = _doc_title(con, r["framework"], r["document"])
    out["text"] = text
    out["refs"] = json.loads(r["refs"])
    extra = json.loads(r["extra"])
    extra.pop("aliases", None)
    out["extra"] = extra
    out["maps"] = [dict(m) for m in con.execute("SELECT ns, target, rel FROM maps WHERE uid=?", (uid,))]
    return out


def req_list(framework: str, document: str | None = None, parent: str | None = None, severity: str | None = None,
             profile: str | None = None, include: list[str] | None = None, offset: int = 0, limit: int = 100) -> dict:
    """Элементы документа по порядку — чек-лист для сверки конфигурации.

    document: id или часть названия (для стандартов с одним документом можно не указывать).
    parent: подстрока раздела/родителя ("AC-2", "Mail Delegation"); severity: "CAT I", "SHALL"…;
    profile: базовый набор/профиль ("HIGH", "Automated_Check"). include: текстовые поля к каждому элементу,
    например ["check", "fix"] (STIG) или ["description"]. limit до 200 (с include — до 50).
    """
    con = db()
    sql, args = "SELECT * FROM items WHERE framework=?", [framework]
    if document:
        sql += " AND document=?"
        args.append(_resolve_doc(con, framework, document))
    if parent:
        sql += " AND (parent LIKE ? OR item_id LIKE ?)"
        args += [f"%{parent}%", f"{parent}%"]
    if severity:
        sql += " AND severity LIKE ?"
        args.append(f"%{severity}%")
    if profile:
        sql += " AND profiles LIKE ?"
        args.append(f'%"{profile}%')
    total = con.execute(sql.replace("SELECT *", "SELECT count(*)"), args).fetchone()[0]
    cap = 50 if include else 200
    rows = con.execute(sql + " ORDER BY document, sort_key LIMIT ? OFFSET ?",
                       args + [max(1, min(limit, cap)), max(0, offset)]).fetchall()
    items = []
    for r in rows:
        d = _summary(r)
        if include:
            t = json.loads(r["text"])
            d.update({f: t.get(f) for f in include if t.get(f)})
        items.append(d)
    nxt = offset + len(rows)
    return {"total": total, "offset": offset, "next_offset": nxt if nxt < total else None, "items": items}


def _ids_of(con, uid):
    return [(r["ns"], r["target"]) for r in con.execute("SELECT ns, target FROM self_ids WHERE uid=?", (uid,))]


def _items_for(con, ns, target, prefix=False):
    """Элементы, которые сами являются (ns, target), и элементы, которые на него ссылаются."""
    op, val = ("LIKE", target + "%") if prefix else ("=", target)
    selves = [r["uid"] for r in con.execute(f"SELECT uid FROM self_ids WHERE ns=? AND target {op} ?", (ns, val))]
    refs = con.execute(f"SELECT uid, rel, target FROM maps WHERE ns=? AND target {op} ?", (ns, val)).fetchall()
    return selves, refs


def _cis_con():
    from secreqs.sources.cis import DB as CIS_DB
    if not os.path.exists(CIS_DB):
        return None
    con = sqlite3.connect(f"file:{CIS_DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _cis_by_control(version, control, limit):
    con = _cis_con()
    if not con:
        return None
    rows = con.execute("SELECT c.uid, b.title, r.rec_id, r.title FROM rec_controls c JOIN recs r ON r.uid=c.uid "
                       "JOIN benchmarks b ON b.id=c.benchmark_id WHERE c.version=? AND c.control=? AND b.is_stig=0 "
                       "LIMIT ?", (version, control, limit)).fetchall()
    total = con.execute("SELECT count(*) FROM rec_controls c JOIN benchmarks b ON b.id=c.benchmark_id "
                        "WHERE c.version=? AND c.control=? AND b.is_stig=0", (version, control)).fetchone()[0]
    return {"total": total, "sample": [{"uid": u, "benchmark": b, "id": i, "title": t} for u, b, i, t in rows]}


# Продукт в ссылках ComplianceAsCode/Prowler (ns cis-benchmark: "<продукт>[ <версия>]:<номер>") → слова названия CIS
CIS_PRODUCTS = {
    "al2023": "amazon linux 2023", "almalinux9": "almalinux os 9", "debian11": "debian linux 11",
    "debian12": "debian linux 12", "debian13": "debian 13", "eks": "amazon elastic kubernetes service eks benchmark",
    "ol7": "oracle linux 7", "ol8": "oracle linux 8", "ol9": "oracle linux 9", "rhel8": "red hat enterprise linux 8",
    "rhel9": "red hat enterprise linux 9", "rhel10": "red hat enterprise linux 10", "sle12": "suse linux enterprise 12",
    "sle15": "suse linux enterprise 15", "ubuntu2204": "ubuntu linux 22 04", "ubuntu2404": "ubuntu linux 24 04",
    "ocp4": "red hat openshift container platform", "aws": "amazon web services foundations",
    "azure": "microsoft azure foundations", "gcp": "google cloud platform foundation", "kubernetes": "kubernetes benchmark",
    "m365": "microsoft 365 foundations", "googleworkspace": "google workspace foundations", "github": "github",
    "oraclecloud": "oracle cloud infrastructure foundations", "alibabacloud": "alibaba cloud foundation",
}


def _cis_bench(con, product):
    words = CIS_PRODUCTS.get(product)
    if not words:
        return None
    w = words.split()
    rows = con.execute("SELECT id, title, version FROM benchmarks WHERE is_stig=0" +
                       " AND (' ' || title_norm || ' ') LIKE ?" * len(w) + " ORDER BY length(title) LIMIT 1",
                       [f"% {x} %" if len(x) <= 3 else f"%{x}%" for x in w]).fetchone()
    return rows


STOP = {"ensure", "the", "and", "for", "are", "that", "set", "configured", "with", "all", "enabled", "disabled",
        "not", "is", "use", "used", "using", "has", "have", "must", "should", "only", "from", "into", "this", "any"}


def _words(s):
    return {w for w in re.findall(r"[a-z0-9]{3,}", (s or "").lower()) if w not in STOP}


def _same_topic(a, b) -> bool:
    return bool(_words(a) & _words(b))


_LATEST: dict[str, tuple] = {}


def _vkey(target):
    v = target.split(":", 1)[0].partition(" ")[2]
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _latest_version(product):
    """Самая новая версия бенчмарка продукта среди ссылок источников (у Prowler — несколько версий CIS)."""
    if product not in _LATEST:
        found = [t for (t,) in db().execute("SELECT DISTINCT target FROM maps WHERE ns='cis-benchmark' AND target LIKE ?",
                                            (f"{product} %",))]
        _LATEST[product] = max((_vkey(t) for t in found), default=())
    return _LATEST[product]


def _cis_from_ref(target, src_title=None):
    """ns cis-benchmark → рекомендация в нашей базе CIS (последняя версия бенчмарка).
    Ссылки на старые версии бенчмарка не разрешаются: номера между версиями меняются."""
    con = _cis_con()
    if not con or ":" not in target:
        return None
    prod, rec = target.split(":", 1)
    product = prod.split()[0]
    if " " in prod and _vkey(target) != _latest_version(product):
        return None
    b = _cis_bench(con, product)
    if not b:
        return None
    r = con.execute("SELECT uid, rec_id, title FROM recs WHERE benchmark_id=? AND rec_id=? ORDER BY uid", (b["id"], rec)).fetchone()
    if not r:
        return None
    src_ver = prod.split(" ", 1)[1] if " " in prod else "версии источника (не указана)"
    out = {"uid": r["uid"], "benchmark": f'{b["title"]} v{b["version"]}', "id": r["rec_id"], "title": r["title"],
           "note": f"номер по CIS {src_ver}, в базе v{b['version']}"}
    if src_title is not None:
        out["match"] = "likely" if _same_topic(src_title, r["title"]) else "check: названия расходятся, вероятно другая версия"
    return out


def _cis_targets(uid):
    """CIS-рекомендация из нашей базы → цели для поиска связей (ссылки CaC/Prowler по продукту и CIS Controls)."""
    con = _cis_con()
    if not con:
        raise ToolError("База CIS не подключена")
    r = con.execute("SELECT r.*, b.title AS btitle, b.title_norm AS bnorm FROM recs r JOIN benchmarks b ON b.id=r.benchmark_id "
                    "WHERE r.uid=?", (uid,)).fetchone()
    if not r:
        raise ToolError(f"Нет рекомендации {uid}")
    controls = [("cis-controls-v8", c["control"]) for c in json.loads(r["cis_controls"]) if c.get("version") == "v8" and c.get("control")]
    targets = []
    prods = [p for p in CIS_PRODUCTS if (b := _cis_bench(con, p)) and b["id"] == r["benchmark_id"]]
    cat = db()
    vkey = _vkey
    for p in prods:
        found = [t for (t,) in cat.execute("SELECT DISTINCT target FROM maps WHERE ns='cis-benchmark' AND (target=? OR target LIKE ?)",
                                           (f"{p}:{r['rec_id']}", f"{p} %:{r['rec_id']}"))]
        # у Prowler ссылки на несколько версий бенчмарка: берём самую новую, нумерация между версиями меняется
        latest = max((vkey(t) for t in found), default=None)
        targets += [("cis-benchmark", t) for t in found if vkey(t) == latest]
    targets += controls  # сначала прямые ссылки по номеру, потом общие CIS Controls
    return {"uid": uid, "title": f'{r["rec_id"]} {r["title"]}', "benchmark": r["btitle"], "_cis_title": r["title"]}, targets


SPECIFIC_NS = {"stig", "stig-id", "cis-benchmark", "prowler-check", "cac-rule", "attack", "atlas", "cwe", "capec",
               "d3fend", "cve", "scuba-policy", "kyverno-policy", "k8s-pss", "asvs", "masvs", "owasp-llm",
               "cis-controls-v8"}


def req_related(uid: str | None = None, ns: str | None = None, id: str | None = None, broad: bool = False,
                include_enhancements: bool = False, per_framework: int = 10) -> dict:
    """Связи требования с другими стандартами (crosswalk).

    По элементу (uid): куда он ссылается и какие элементы других стандартов связаны с ним. Работает и для
    рекомендаций CIS из cis_* (uid вида cis:27155:4.3.1) — через ссылки ComplianceAsCode/Prowler и CIS Controls.
    По умолчанию раскрываются только конкретные связи (STIG-ID, CIS, проверки Prowler, правила ComplianceAsCode,
    ATT&CK, CWE…); broad=True раскрывает и общие меры (NIST 800-53, CCI, SRG, ISO, PCI…) — это даёт сотни
    «соседей» по общей мере. По идентификатору (ns + id, например ns="nist-800-53", id="AC-2"; ns="attack",
    id="T1566"; ns="iso27001", id="A.8.9"; ns="pci-dss", id="8.3.1"): всё, что на него ссылается, по стандартам.
    include_enhancements: для 800-53 учитывать и улучшения (AC-2 → AC-2(1)…). per_framework: примеров на стандарт.
    """
    con = db()
    lim = max(1, min(per_framework, 50))
    targets: list[tuple[str, str]] = []
    out: dict = {}
    if uid and uid.startswith("cis:"):
        out["item"], targets = _cis_targets(uid)
    elif uid:
        r = con.execute("SELECT * FROM items WHERE uid=?", (uid,)).fetchone()
        if not r:
            raise ToolError(f"Нет элемента {uid}")
        out["item"] = _summary(r)
        own = [dict(m) for m in con.execute("SELECT ns, target, rel FROM maps WHERE uid=?", (uid,))]
        out["maps_to"] = own[:200]
        targets = [(m["ns"], m["target"]) for m in own if broad or m["ns"] in SPECIFIC_NS]
        targets += _ids_of(con, uid)
    elif ns and id:
        known = {r[0] for r in con.execute("SELECT DISTINCT ns FROM maps UNION SELECT DISTINCT ns FROM self_ids")}
        if ns not in known:
            raise ToolError(f"Неизвестное пространство имён {ns}. Есть: {', '.join(sorted(known))}")
        targets = [(ns, norm_ref(ns, id))]
    else:
        raise ToolError("Нужен uid или ns + id")

    src_title = (out.get("item") or {}).get("title") if uid and not uid.startswith("cis:") else None
    cis_title = (out.get("item") or {}).pop("_cis_title", None)
    groups: dict[str, dict] = {}
    seen = {uid}

    def add(group, item):
        g = groups.setdefault(group, {"count": 0, "items": []})
        g["count"] += 1
        if len(g["items"]) < lim:
            g["items"].append(item)

    for tns, tid in dict.fromkeys(targets):
        selves, refs = _items_for(con, tns, tid)
        if include_enhancements and tns == "nist-800-53" and "." not in tid:
            s2, r2 = _items_for(con, tns, tid + ".", prefix=True)
            selves += s2
            refs = list(refs) + list(r2)
        for u in selves:
            if u not in seen:
                seen.add(u)
                row = con.execute("SELECT * FROM items WHERE uid=?", (u,)).fetchone()
                add(row["framework"], {**_summary(row), "via": f"is {tns}:{tid}"})
        for ref in refs:
            u = ref["uid"]
            if u in seen:
                continue
            seen.add(u)
            row = con.execute("SELECT * FROM items WHERE uid=?", (u,)).fetchone()
            it = {**_summary(row), "via": f'{ref["rel"]} {tns}:{ref["target"]}',
                  "document_title": _doc_title(con, row["framework"], row["document"])}
            if tns == "cis-benchmark" and cis_title:
                it["match"] = "likely" if _same_topic(cis_title, row["title"]) else "check: названия расходятся"
            add(row["framework"], it)
        if tns == "cis-benchmark":
            c = _cis_from_ref(tid, src_title)
            if c and c["uid"] not in seen:
                seen.add(c["uid"])
                add("cis", {**c, "via": f"cis-benchmark:{tid}"})
        if tns in ("cis-controls-v8", "cis-controls-v7"):
            cis = _cis_by_control(tns[-2:], tid, lim)
            if cis:
                g = groups.setdefault("cis (по CIS Controls)", {"count": 0, "items": []})
                g["count"] += cis["total"]
                g["items"] = (g["items"] + cis["sample"])[:lim]
    out["related"] = groups
    out["note"] = ("Связи взяты из первоисточников (CCI-список DISA, сопоставления в SCuBA, OSCAL, ComplianceAsCode и т.д.). "
                   "Связь через общую меру 800-53 означает близкое, но не обязательно идентичное требование.")
    return out


def req_cve(cve: str, nvd: bool = True) -> dict:
    """Сводка по CVE: есть ли в CISA KEV (эксплуатируется в атаках, срок и требуемое действие, шифровальщики),
    EPSS (вероятность эксплуатации за 30 дней и перцентиль), слабости CWE с мерами, и — если nvd=True —
    актуальные данные NVD (описание, CVSS, CWE, ссылки; живой запрос к services.nvd.nist.gov).
    Разборы CVE из HF-датасета — hf_find_cve."""
    import urllib.request
    m = re.search(r"CVE-\d{4}-\d{4,7}", cve.upper())
    if not m:
        raise ToolError("Ожидается идентификатор вида CVE-2024-12345")
    c = m.group(0)
    con = db()
    out: dict = {"cve": c}
    kev = con.execute("SELECT * FROM items WHERE framework='cisa-kev' AND item_id=?", (c,)).fetchone()
    out["kev"] = {**_summary(kev), **json.loads(kev["extra"]), "required_action": json.loads(kev["text"]).get("fix")} if kev else None
    sc = con.execute("SELECT score, percentile, date FROM cve_scores WHERE cve=? AND source='epss'", (c,)).fetchone()
    out["epss"] = dict(sc) if sc else None
    cwes = set()
    if kev:
        cwes |= {r["target"] for r in con.execute("SELECT target FROM maps WHERE uid=? AND ns='cwe'", (kev["uid"],))}
    if nvd:
        try:
            req = urllib.request.Request(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={c}",
                                         headers={"User-Agent": "Mozilla/5.0 (sec-reqs)"})
            with urllib.request.urlopen(req, timeout=30) as r:
                v = (json.load(r).get("vulnerabilities") or [{}])[0].get("cve")
            if v:
                metrics = v.get("metrics", {})
                cvss = []
                for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    for x in metrics.get(k, [])[:1]:
                        d = x.get("cvssData", {})
                        cvss.append({"version": d.get("version"), "score": d.get("baseScore"),
                                     "severity": d.get("baseSeverity") or x.get("baseSeverity"),
                                     "vector": d.get("vectorString"), "source": x.get("source")})
                for wk in v.get("weaknesses", []):
                    cwes |= {d["value"] for d in wk.get("description", []) if d["value"].startswith("CWE-")}
                out["nvd"] = {"published": v.get("published"), "modified": v.get("lastModified"),
                              "status": v.get("vulnStatus"),
                              "description": next((d["value"] for d in v.get("descriptions", []) if d["lang"] == "en"), None),
                              "cvss": cvss, "references": [r["url"] for r in v.get("references", [])][:15]}
            else:
                out["nvd"] = None
        except Exception as e:
            out["nvd"] = {"error": f"NVD недоступен: {type(e).__name__}"}
    out["cwe"] = []
    for w in sorted(cwes):
        r = con.execute("SELECT * FROM items WHERE framework='cwe' AND item_id=?", (w,)).fetchone()
        if r:
            t = json.loads(r["text"])
            out["cwe"].append({"uid": r["uid"], "id": w, "title": r["title"], "mitigations": (t.get("fix") or "")[:1500]})
        else:
            out["cwe"].append({"id": w})
    return out


TOOLS = [req_frameworks, req_documents, req_search, req_get, req_list, req_related, req_cve]


class CatalogSource(Source):
    name = "req"
    title = "Каталог требований (STIG, SCuBA, NIST, OWASP, MITRE…)"
    instructions = INSTRUCTIONS
    get_tool = "req_get(uid=…)"

    def available(self):
        if not os.path.exists(DB):
            return False, f"нет базы {DB}; собрать: .venv/bin/python -m secreqs.catalog.build"
        return True, ""

    def register(self, mcp):
        for fn in TOOLS:
            mcp.tool(annotations=RO)(fn)

    def stats(self):
        con = db()
        st = read_status("catalog") or {}
        problems = {**st.get("failed", {}), **{n: "нет данных" for n in st.get("missing_loaders", [])}}
        return {**({"warnings": [f"загрузчик {k}: {v}" for k, v in problems.items()]} if problems else {}),
                "built_at": st.get("finished_at"),
                "frameworks": [r[0] for r in con.execute("SELECT id FROM frameworks ORDER BY id")],
                "items": con.execute("SELECT count(*) FROM items").fetchone()[0],
                "mappings": con.execute("SELECT count(*) FROM maps").fetchone()[0]}

    def search(self, query, limit=5):
        con = db()
        _, rows = _fts(con, query, limit=limit * 5)
        rows = _dedupe(rows, limit)
        return [{"id": r["uid"], "title": f'{r["item_id"]} {r["title"]}'[:200],
                 "where": _doc_title(con, r["framework"], r["document"]),
                 "snippet": _summary(r, query).get("snippet", "")} for r in rows]
