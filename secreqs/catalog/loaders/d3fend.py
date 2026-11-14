"""MITRE D3FEND: каталог защитных техник (Harden, Detect, Isolate, Deceive, Evict, Restore, Model) с
определениями и статьями. Связи с ATT&CK в онтологии выводятся логически и здесь не загружаются. MIT."""
from __future__ import annotations

import json
import os

from secreqs.catalog.model import RAW, Writer, fetch

URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
SELF_NS = {"d3fend": "d3fend"}


def label(x):
    v = x.get("rdfs:label")
    return v if isinstance(v, str) else (v.get("@value") if isinstance(v, dict) else None)


def load() -> int:
    d = json.load(open(fetch(URL, os.path.join(RAW, "mitre", "d3fend.json"), max_age_days=30), encoding="utf-8"))
    g = {x["@id"]: x for x in d["@graph"]}
    ver = next((x.get("owl:versionInfo") for x in d["@graph"] if "owl:versionInfo" in x), None)
    w = Writer("d3fend")
    w.framework("d3fend", "MITRE D3FEND", "controls", "MITRE", "MIT", "https://d3fend.mitre.org/", version=ver,
                description="Граф знаний защитных техник кибербезопасности (что делать защитнику): Model, Harden, "
                            "Detect, Isolate, Deceive, Evict, Restore.")
    w.document("d3fend", "techniques", "D3FEND defensive techniques", version=ver)

    def chain(x):
        names, seen = [], set()
        while x and "rdfs:subClassOf" in x:
            sc = x["rdfs:subClassOf"]
            sc = sc if isinstance(sc, list) else [sc]
            nxt = next((g.get(s["@id"]) for s in sc if isinstance(s, dict) and s.get("@id") in g
                        and "d3f:d3fend-id" in g[s["@id"]]), None)
            if not nxt or nxt["@id"] in seen:
                break
            seen.add(nxt["@id"])
            names.append(label(nxt))
            x = nxt
        return " > ".join(reversed([n for n in names if n]))

    for x in d["@graph"]:
        did = x.get("d3f:d3fend-id")
        if not did or not did.startswith("D3-") or x.get("owl:deprecated"):
            continue
        w.item("d3fend", "techniques", did, label(x) or did, kind="defensive-technique", parent=chain(x) or None,
               text={"description": x.get("d3f:definition"), "article": x.get("d3f:kb-article"),
                     "synonyms": ", ".join(x["d3f:synonym"]) if isinstance(x.get("d3f:synonym"), list) else x.get("d3f:synonym")},
               refs=[f"https://d3fend.mitre.org/technique/{x['@id']}/"])
    return w.close()
