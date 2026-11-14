"""MITRE CWE (слабости ПО) и CAPEC (шаблоны атак) из XML-выгрузок, со связями CWE ↔ CAPEC ↔ ATT&CK.
Условия использования CWE/CAPEC: свободно с указанием MITRE."""
from __future__ import annotations

import io
import os
import re
import xml.etree.ElementTree as ET
import zipfile

from secreqs.catalog.model import RAW, Writer, fetch

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
SELF_NS = {"cwe": "cwe", "capec": "capec"}


def L(tag):
    return tag.rsplit("}", 1)[-1]


def kid(el, name):
    for c in el:
        if L(c.tag) == name:
            return c
    return None


def kids(el, name):
    return [c for c in el if L(c.tag) == name] if el is not None else []


def txt(el):
    if el is None:
        return None
    s = " ".join(t.strip() for t in el.itertext() if t.strip())
    return re.sub(r"\s+", " ", s).strip() or None


def mitigations(el):
    out = []
    for m in kids(kid(el, "Potential_Mitigations") if el is not None else None, "Mitigation"):
        phase = ", ".join(txt(p) for p in kids(m, "Phase") if txt(p))
        d = txt(kid(m, "Description"))
        if d:
            out.append(f"- [{phase}] {d}" if phase else f"- {d}")
    for m in kids(kid(el, "Mitigations") if el is not None else None, "Mitigation"):
        if txt(m):
            out.append(f"- {txt(m)}")
    return "\n".join(out) or None


def load_cwe(w):
    path = fetch(CWE_URL, os.path.join(RAW, "mitre", "cwec_latest.xml.zip"), max_age_days=30)
    zf = zipfile.ZipFile(path)
    root = ET.parse(io.BytesIO(zf.read(zf.namelist()[0]))).getroot()
    ver, date = root.get("Version"), root.get("Date")
    w.framework("cwe", "MITRE Common Weakness Enumeration (CWE)", "weaknesses", "MITRE", "CWE Terms of Use",
                "https://cwe.mitre.org/", version=ver, published=date,
                description="Классификация слабостей ПО и оборудования с последствиями, способами обнаружения и мерами.")
    w.document("cwe", "weaknesses", f"CWE {ver}", version=ver, date=date)
    for wk in kids(kid(root, "Weaknesses"), "Weakness"):
        if wk.get("Status") == "Deprecated":
            continue
        cid = f'CWE-{wk.get("ID")}'
        maps = [{"ns": "capec", "id": f'CAPEC-{r.get("CAPEC_ID")}', "rel": "attacked-by"}
                for r in kids(kid(wk, "Related_Attack_Patterns"), "Related_Attack_Pattern")]
        parent = None
        for r in kids(kid(wk, "Related_Weaknesses"), "Related_Weakness"):
            if r.get("Nature") == "ChildOf" and r.get("Ordinal") == "Primary":
                parent = f'CWE-{r.get("CWE_ID")}'
                maps.append({"ns": "cwe", "id": parent, "rel": "child-of"})
        cons = "\n".join(f'- {", ".join(txt(s) for s in kids(c, "Scope") if txt(s))}: '
                         f'{", ".join(txt(i) for i in kids(c, "Impact") if txt(i))}'
                         for c in kids(kid(wk, "Common_Consequences"), "Consequence"))
        det = "\n".join(f'- {txt(kid(d, "Method"))}: {txt(kid(d, "Description"))}'
                        for d in kids(kid(wk, "Detection_Methods"), "Detection_Method"))
        w.item("cwe", "weaknesses", cid, wk.get("Name"), kind=f'weakness ({wk.get("Abstraction")})', parent=parent,
               severity=txt(kid(wk, "Likelihood_Of_Exploit")),
               text={"description": txt(kid(wk, "Description")), "extended": txt(kid(wk, "Extended_Description")),
                     "consequences": cons or None, "detection": det or None, "fix": mitigations(wk)},
               refs=[f"https://cwe.mitre.org/data/definitions/{wk.get('ID')}.html"], maps=maps,
               extra={"abstraction": wk.get("Abstraction"), "status": wk.get("Status")})


def load_capec(w):
    root = ET.parse(fetch(CAPEC_URL, os.path.join(RAW, "mitre", "capec_latest.xml"), max_age_days=30)).getroot()
    ver, date = root.get("Version"), root.get("Date")
    w.framework("capec", "MITRE CAPEC (Common Attack Pattern Enumeration and Classification)", "threats", "MITRE",
                "CAPEC Terms of Use", "https://capec.mitre.org/", version=ver, published=date,
                description="Каталог шаблонов атак: предпосылки, ход атаки, последствия, меры, связи с CWE и ATT&CK.")
    w.document("capec", "patterns", f"CAPEC {ver}", version=ver, date=date)
    for ap in kids(kid(root, "Attack_Patterns"), "Attack_Pattern"):
        if ap.get("Status") == "Deprecated":
            continue
        cid = f'CAPEC-{ap.get("ID")}'
        maps = [{"ns": "cwe", "id": f'CWE-{r.get("CWE_ID")}', "rel": "exploits"}
                for r in kids(kid(ap, "Related_Weaknesses"), "Related_Weakness")]
        for tm in kids(kid(ap, "Taxonomy_Mappings"), "Taxonomy_Mapping"):
            if "ATTACK" in (tm.get("Taxonomy_Name") or "").upper():
                e = txt(kid(tm, "Entry_ID"))
                if e:
                    maps.append({"ns": "attack", "id": "T" + e.lstrip("T"), "rel": "related"})
        parent = None
        for r in kids(kid(ap, "Related_Attack_Patterns"), "Related_Attack_Pattern"):
            if r.get("Nature") == "ChildOf":
                parent = f'CAPEC-{r.get("CAPEC_ID")}'
        steps = "\n".join(f'{txt(kid(s, "Step"))}. [{txt(kid(s, "Phase"))}] {txt(kid(s, "Description"))}'
                          for s in kids(kid(ap, "Execution_Flow"), "Attack_Step"))
        w.item("capec", "patterns", cid, ap.get("Name"), kind=f'attack-pattern ({ap.get("Abstraction")})',
               parent=parent, severity=txt(kid(ap, "Typical_Severity")),
               text={"description": txt(kid(ap, "Description")),
                     "prerequisites": "\n".join(f"- {txt(p)}" for p in kids(kid(ap, "Prerequisites"), "Prerequisite")) or None,
                     "execution_flow": steps or None, "fix": mitigations(ap)},
               refs=[f"https://capec.mitre.org/data/definitions/{ap.get('ID')}.html"], maps=maps,
               extra={"likelihood": txt(kid(ap, "Likelihood_Of_Attack"))})


def load() -> int:
    w = Writer("cwe")
    load_cwe(w)
    load_capec(w)
    return w.close()
