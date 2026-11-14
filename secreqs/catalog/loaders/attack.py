"""MITRE ATT&CK (Enterprise, Mobile, ICS) из STIX 2.1 (mitre-attack/attack-stix-data): тактики, техники,
меры защиты (M####), группы, ПО, кампании, со связями «мера → техника», «группа/ПО → техника», CAPEC.
Условия использования ATT&CK: свободное использование с указанием MITRE."""
from __future__ import annotations

import json
import os

from secreqs.catalog.model import RAW, Writer, fetch, fetch_json

INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
SELF_NS = {"attack": "attack"}
KINDS = {"x-mitre-tactic": "tactic", "attack-pattern": "technique", "course-of-action": "mitigation",
         "intrusion-set": "group", "malware": "software", "tool": "software", "campaign": "campaign"}


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return r.get("external_id"), r.get("url")
    return None, None


def load() -> int:
    raw = os.path.join(RAW, "mitre")
    idx = fetch_json(INDEX, os.path.join(raw, "attack-index.json"), max_age_days=7)
    w = Writer("attack")
    first = True
    for col in idx["collections"]:
        v = col["versions"][0]
        dom = col["name"].split()[0].lower()   # enterprise / mobile / ics
        bundle = json.load(open(fetch(v["url"], os.path.join(raw, os.path.basename(v["url"])), max_age_days=60),
                                encoding="utf-8"))
        if first:
            w.framework("attack", "MITRE ATT&CK", "threats", "MITRE", "ATT&CK Terms of Use (free with attribution)",
                        "https://attack.mitre.org/", version=v["version"], published=v["modified"][:10],
                        description="База тактик и техник противника, мер защиты (Mitigations), групп и ПО. "
                                    "Документы: <домен>-techniques / -mitigations / -groups / -software / -tactics.")
            first = False
        objs = {o["id"]: o for o in bundle["objects"]}
        rels = [o for o in bundle["objects"] if o["type"] == "relationship" and not o.get("revoked")]
        out_maps: dict[str, list] = {}
        for r in rels:
            s, t = objs.get(r["source_ref"]), objs.get(r["target_ref"])
            if not s or not t:
                continue
            sid, _ = ext_id(s)
            tid, _ = ext_id(t)
            if not sid or not tid:
                continue
            rt = r["relationship_type"]
            if rt == "mitigates":
                out_maps.setdefault(r["source_ref"], []).append({"ns": "attack", "id": tid, "rel": "mitigates"})
                out_maps.setdefault(r["target_ref"], []).append({"ns": "attack", "id": sid, "rel": "mitigated-by"})
            elif rt == "uses" and t["type"] == "attack-pattern":
                out_maps.setdefault(r["source_ref"], []).append({"ns": "attack", "id": tid, "rel": "uses"})
            elif rt == "subtechnique-of":
                out_maps.setdefault(r["source_ref"], []).append({"ns": "attack", "id": tid, "rel": "subtechnique-of"})
        tactic_names = {o.get("x_mitre_shortname"): ext_id(o)[0] for o in objs.values() if o["type"] == "x-mitre-tactic"}
        docs = set()
        for o in objs.values():
            kind = KINDS.get(o["type"])
            if not kind or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            eid, url = ext_id(o)
            if not eid:
                continue
            doc = f"{dom}-{kind if kind != 'software' else 'software'}s" if kind != "tactic" else f"{dom}-tactics"
            if doc not in docs:
                docs.add(doc)
                w.document("attack", doc, f'{col["name"]}: {kind}s', version=v["version"], date=v["modified"][:10])
            maps = list(out_maps.get(o["id"], []))
            tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])]
            maps += [{"ns": "attack", "id": tactic_names[t], "rel": "tactic"} for t in tactics if tactic_names.get(t)]
            for r in o.get("external_references", []):
                if r.get("source_name") == "capec" and r.get("external_id"):
                    maps.append({"ns": "capec", "id": r["external_id"], "rel": "related"})
            w.item("attack", doc, eid, o.get("name"), kind=kind,
                   parent=eid.split(".")[0] if kind == "technique" and "." in eid else None,
                   profiles=o.get("x_mitre_platforms") or [],
                   text={"description": o.get("description"), "detection": o.get("x_mitre_detection"),
                         "aliases": ", ".join(o.get("aliases") or o.get("x_mitre_aliases") or [])},
                   refs=[url] if url else [], maps=maps,
                   extra={"tactics": tactics, "domain": dom, "modified": o.get("modified", "")[:10],
                          "is_subtechnique": o.get("x_mitre_is_subtechnique", False)})
    return w.close()
