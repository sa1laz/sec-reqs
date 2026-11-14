"""DISA STIG и SRG: квартальная библиотека XCCDF с cyber.mil + список CCI (CCI → NIST 800-53 rev5).

Каждое правило: V-id (группа), SV-id и STIG-ID, критичность CAT I–III, обсуждение, проверка, исправление,
ссылки на CCI и через них — на меры NIST 800-53. Лицензия: документы DoD, свободное распространение.
"""
from __future__ import annotations

import datetime as dt
import io
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from html import unescape

from secreqs.catalog.model import RAW, Writer, fetch

BASE = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
SELF_NS = {"stig": "stig", "disa-cci": "cci"}
CAT = {"high": "CAT I (high)", "medium": "CAT II (medium)", "low": "CAT III (low)"}


def library_url() -> tuple[str, str]:
    """Самая свежая квартальная компиляция: перебор месяцев назад от текущего."""
    import urllib.request
    d = dt.date.today().replace(day=1)
    for _ in range(15):
        name = f"U_SRG-STIG_Library_{d.strftime('%B')}_{d.year}.zip"
        try:
            req = urllib.request.Request(BASE + name, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                if r.status == 200 and "zip" in (r.headers.get("Content-Type") or ""):
                    return BASE + name, name
        except Exception:
            pass
        d = (d - dt.timedelta(days=1)).replace(day=1)
    raise RuntimeError("не нашёл библиотеку STIG за последние 15 месяцев")


def xccdf_files(zf: zipfile.ZipFile, depth=0):
    """Все XCCDF внутри (в т.ч. во вложенных zip)."""
    for n in zf.namelist():
        low = n.lower()
        if low.endswith("xccdf.xml"):
            yield n, zf.read(n)
        elif low.endswith(".zip") and depth < 3:
            try:
                yield from xccdf_files(zipfile.ZipFile(io.BytesIO(zf.read(n))), depth + 1)
            except zipfile.BadZipFile:
                pass


def local(tag):
    return tag.rsplit("}", 1)[-1]


def child(el, name):
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def children(el, name):
    return [c for c in el if local(c.tag) == name]


def text_of(el):
    return "".join(el.itertext()).strip() if el is not None else None


def vuln_parts(desc: str) -> dict:
    """Описание правила STIG — экранированный псевдо-XML <VulnDiscussion>…<Mitigations>…"""
    s = unescape(desc or "")
    out = {}
    for tag in ("VulnDiscussion", "FalsePositives", "FalseNegatives", "Documentable", "Mitigations",
                "SeverityOverrideGuidance", "PotentialImpacts", "ThirdPartyTools", "MitigationControl",
                "Responsibility", "IAControls"):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", s, re.S)
        if m and m.group(1).strip() and m.group(1).strip().lower() not in ("false", "none"):
            out[tag] = m.group(1).strip()
    if not out and s.strip():
        out["VulnDiscussion"] = re.sub(r"<[^>]+>", " ", s).strip()
    return out


def load_cci(w: Writer, path: str) -> dict[str, list[str]]:
    zf = zipfile.ZipFile(path)
    root = ET.fromstring(zf.read("U_CCI_List.xml"))
    meta = {local(c.tag): text_of(c) for c in (child(root, "metadata") or [])}
    w.framework("disa-cci", "DISA Control Correlation Identifier (CCI) List", "crosswalk", "DISA",
                "U.S. Government work", "https://public.cyber.mil/stigs/cci/", version=meta.get("version"),
                published=meta.get("publishdate"),
                description="Атомарные требования, на которые ссылаются STIG/SRG; связывают их с NIST SP 800-53.")
    w.document("disa-cci", "cci", "CCI List", version=meta.get("version"), date=meta.get("publishdate"))
    cci_map = {}
    for it in children(child(root, "cci_items"), "cci_item"):
        cid = it.get("id")
        nist = []
        for ref in children(child(it, "references") or ET.Element("x"), "reference"):
            if "800-53" in (ref.get("title") or "") and "Revision 5" in (ref.get("title") or ""):
                nist.append(ref.get("index"))
        cci_map[cid] = nist
        w.item("disa-cci", "cci", cid, text_of(child(it, "definition"))[:200] if child(it, "definition") is not None else cid,
               kind="cci", text={"definition": text_of(child(it, "definition"))},
               extra={"status": text_of(child(it, "status")), "type": text_of(child(it, "type"))},
               maps=[{"ns": "nist-800-53", "id": n.split(" ")[0], "rel": "implements"} for n in nist])
    return cci_map


def load() -> int:
    raw = os.path.join(RAW, "stig")
    url, name = library_url()
    lib = fetch(url, os.path.join(raw, name), max_age_days=90)
    cci = fetch(BASE + "U_CCI_List.zip", os.path.join(raw, "U_CCI_List.zip"), max_age_days=90)
    w = Writer("stig")
    cci_map = load_cci(w, cci)
    w.framework("stig", "DISA STIGs and SRGs", "benchmark", "DISA (U.S. DoD)", "U.S. Government work",
                "https://public.cyber.mil/stigs/", version=name.replace("U_SRG-STIG_Library_", "").replace(".zip", ""),
                description="Security Technical Implementation Guides и Security Requirements Guides: требования к "
                            "настройке ОС, СУБД, сетевого оборудования, приложений и облаков с процедурой проверки "
                            "и исправления. Критичность: CAT I (high) — CAT III (low).")
    seen = set()
    for fname, data in xccdf_files(zipfile.ZipFile(lib)):
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            continue
        bid = root.get("id")
        if not bid or bid in seen:
            continue
        seen.add(bid)
        ver = text_of(child(root, "version"))
        rel = ""
        for pt in children(root, "plain-text"):
            if pt.get("id") == "release-info":
                rel = text_of(pt) or ""
        m = re.search(r"Release:\s*(\S+)", rel)
        version = f"V{ver}R{m.group(1)}" if ver and m else ver
        date = re.search(r"Benchmark Date:\s*(.+)", rel)
        is_srg = "_SRG" in fname.upper() or bid.upper().endswith("SRG")
        w.document("stig", bid, text_of(child(root, "title")), version=version,
                   date=date.group(1).strip() if date else None, description=text_of(child(root, "description")),
                   extra={"type": "SRG" if is_srg else "STIG", "file": os.path.basename(fname)})
        for g in root.iter():
            if local(g.tag) != "Group":
                continue
            rule = child(g, "Rule")
            if rule is None:
                continue
            vid = g.get("id")
            parts = vuln_parts(text_of(child(rule, "description")))
            check = child(rule, "check")
            ccis = [text_of(i) for i in children(rule, "ident") if "cci" in (i.get("system") or "").lower()]
            maps = [{"ns": "cci", "id": c, "rel": "references"} for c in ccis]
            for c in ccis:
                maps += [{"ns": "nist-800-53", "id": n.split(" ")[0], "rel": "via-cci"} for n in cci_map.get(c, [])]
            srg = text_of(child(g, "title"))
            if srg and srg.startswith("SRG-"):
                maps.append({"ns": "srg", "id": srg, "rel": "implements"})
            stig_id = text_of(child(rule, "version"))
            sev = rule.get("severity")
            w.item("stig", bid, vid, text_of(child(rule, "title")), kind="srg-requirement" if is_srg else "rule",
                   severity=CAT.get(sev, sev),
                   text={"description": parts.pop("VulnDiscussion", None),
                         "check": text_of(child(check, "check-content")) if check is not None else None,
                         "fix": text_of(child(rule, "fixtext")),
                         **{k.lower(): v for k, v in parts.items()}},
                   refs=[f"STIG-ID {stig_id}"] if stig_id else [], maps=maps,
                   extra={"rule_id": rule.get("id"), "stig_id": stig_id, "srg": srg, "weight": rule.get("weight"),
                          "aliases": [{"ns": "stig-id", "id": stig_id}] if stig_id else []})
    return w.close()
