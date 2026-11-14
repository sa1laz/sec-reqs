"""Каталоги NIST в OSCAL (usnistgov/oscal-content): SP 800-53 rev5 с базовыми наборами LOW/MODERATE/HIGH/PRIVACY,
CSF 2.0, SSDF (SP 800-218), SP 800-171 rev3, AI RMF 1.0. Public domain (NIST).
"""
from __future__ import annotations

import os
import re

from secreqs.catalog.model import RAW, Writer, fetch_json

BASE = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/"
CATALOGS = [
    # framework id, путь, ns для связей (None — нет), kind, короткое название
    ("nist-800-53", "SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json", "nist-800-53", "controls",
     "NIST SP 800-53 Rev. 5 Security and Privacy Controls"),
    ("nist-csf-2", "CSF/v2.0/json/NIST_CSF_v2.0_catalog.json", "nist-csf-2", "controls", "NIST Cybersecurity Framework 2.0"),
    ("nist-ssdf", "SP800-218/ver1/json/NIST_SP800-218_ver1_catalog.json", "nist-ssdf", "controls",
     "NIST SP 800-218 Secure Software Development Framework (SSDF) 1.1"),
    ("nist-800-171", "SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json", None, "controls",
     "NIST SP 800-171 Rev. 3 Protecting CUI in Nonfederal Systems"),
    ("nist-ai-rmf", "AI100-1/ver1/json/NIST_AI-RMF_v1_catalog.json", None, "controls",
     "NIST AI Risk Management Framework 1.0"),
]
BASELINES = ["LOW", "MODERATE", "HIGH", "PRIVACY"]
SELF_NS = {fw: ns for fw, _, ns, _, _ in CATALOGS if ns}
PART_TITLES = {"statement": "description", "guidance": "guidance", "overview": "overview", "example": "examples",
               "assessment-objective": "assessment_objective", "assessment-method": "assessment_method",
               "objective": "assessment_objective", "item": None}


def prop(x, name):
    for p in x.get("props", []):
        if p.get("name") == name and not p.get("class") == "zero-padded":
            return p.get("value")
    return None


def render_parts(parts, params, depth=0) -> dict[str, list[str]]:
    """parts OSCAL → {поле: [строки]} с подстановкой параметров."""
    out: dict[str, list[str]] = {}

    def sub(prose):
        def rep(m):
            p = params.get(m.group(1), {})
            lab = p.get("label") or (p.get("select") and "Selection: " + "; ".join(p["select"].get("choice", [])))
            return f"[Assignment: {lab or m.group(1)}]"
        return re.sub(r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}", rep, prose or "")

    def walk(ps, field, d):
        for p in ps:
            f = field or PART_TITLES.get(p.get("name"), p.get("name"))
            lbl = prop(p, "label")
            line = ("  " * d + (f"{lbl} " if lbl else "") + (f"{p['title']} " if p.get("title") else "") + sub(p.get("prose"))).rstrip()
            if line.strip():
                out.setdefault(f or "description", []).append(line)
            if p.get("parts"):
                walk(p["parts"], f, d + 1)

    walk(parts or [], None, depth)
    return out


def load() -> int:
    raw = os.path.join(RAW, "nist")
    w = Writer("nist_oscal")
    base_sets = {}
    for b in BASELINES:
        prof = fetch_json(BASE + f"SP800-53/rev5/json/NIST_SP-800-53_rev5_{b}-baseline_profile.json",
                          os.path.join(raw, f"800-53_{b}.json"), max_age_days=30)
        ids = set()
        for imp in prof["profile"].get("imports", []):
            for inc in imp.get("include-controls", []):
                ids.update(inc.get("with-ids", []))
        base_sets[b] = ids
    for fw, path, ns, kind, title in CATALOGS:
        cat = fetch_json(BASE + path, os.path.join(raw, os.path.basename(path)), max_age_days=30)["catalog"]
        md = cat["metadata"]
        w.framework(fw, title, kind, "NIST", "Public domain (U.S. Government work)",
                    "https://github.com/usnistgov/oscal-content/tree/main/nist.gov/" + path.split("/json/")[0],
                    version=md.get("version"), published=(md.get("published") or md.get("last-modified") or "")[:10],
                    description=md.get("title"))
        w.document(fw, "catalog", md.get("title", title), version=md.get("version"),
                   date=(md.get("last-modified") or "")[:10])

        def walk_controls(ctrls, parent_label):
            for c in ctrls:
                params = {p["id"]: p for p in c.get("params", [])}
                label = prop(c, "label") or c["id"]
                m = re.search(r"\(([\d.]+)\)$", label)   # 800-171: "Account Management (03.01.01)"
                if m and fw == "nist-800-171":
                    label = m.group(1)
                if fw == "nist-ai-rmf":
                    label = c.get("title") or label
                status = prop(c, "status")
                parts = render_parts(c.get("parts"), params)
                text = {k: "\n".join(v) for k, v in parts.items()}
                maps = []
                for l in c.get("links", []):
                    href = l.get("href", "")
                    if href.startswith("#") and ns and l.get("rel") in ("related", "incorporated-into", "moved-to", "required"):
                        maps.append({"ns": ns, "id": href[1:], "rel": l["rel"]})
                profiles = [b for b, s in base_sets.items() if c["id"] in s] if fw == "nist-800-53" else []
                ttl = c.get("title") or label
                if ttl == label and (text.get("overview") or text.get("description")):
                    ttl = (text.get("overview") or text["description"]).split("\n")[0].strip()[:200]
                w.item(fw, "catalog", label, ttl, kind=c.get("class") or "control", parent=parent_label,
                       severity="withdrawn" if status == "withdrawn" else None, profiles=profiles, text=text,
                       maps=maps, extra={"oscal_id": c["id"], "status": status})
                if c.get("controls"):
                    walk_controls(c["controls"], label)

        def walk_groups(groups, parent_label):
            for g in groups:
                gl = prop(g, "label") or g.get("id")
                glabel = gl if g.get("title") and g["title"] in gl else f'{gl}: {g.get("title")}'.strip()
                full = f"{parent_label} > {glabel}" if parent_label else glabel
                if g.get("controls"):
                    walk_controls(g["controls"], full)
                if g.get("groups"):
                    walk_groups(g["groups"], full)

        walk_groups(cat.get("groups", []), None)
        if cat.get("controls"):
            walk_controls(cat["controls"], None)
    return w.close()
