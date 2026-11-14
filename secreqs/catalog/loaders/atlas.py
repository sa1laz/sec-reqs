"""MITRE ATLAS: тактики, техники и меры защиты для атак на системы ИИ (prompt injection, отравление данных,
кража моделей…), со связями «мера → техника» и ссылками на ATT&CK. Apache-2.0."""
from __future__ import annotations

import json
import os
import urllib.request

import yaml

from secreqs.catalog.model import RAW, Writer, fetch, gh_headers

REPO = "mitre-atlas/atlas-data"
SELF_NS = {"atlas": "atlas"}


def load() -> int:
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/latest", headers=gh_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        rel = json.load(r)
    asset = next(a for a in rel["assets"] if a["name"].startswith("ATLAS") and a["name"].endswith(".yaml"))
    d = yaml.safe_load(open(fetch(asset["browser_download_url"], os.path.join(RAW, "atlas", asset["name"]),
                                  max_age_days=30), encoding="utf-8"))
    ver = rel["tag_name"]
    w = Writer("atlas")
    w.framework("atlas", "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)", "threats", "MITRE",
                "Apache-2.0", "https://atlas.mitre.org/", version=ver, published=rel["published_at"][:10],
                description="Матрица тактик и техник атак на системы машинного обучения и LLM с мерами защиты и "
                            "разборами реальных случаев.")
    mitig_of, tactics_of, mitigates = {}, {}, {}
    for src, rels in d.get("relationships", {}).items():
        for typ, lst in rels.items():
            for x in lst:
                if typ == "mitigates":
                    mitig_of.setdefault(x["target"], []).append(x["source"])
                    mitigates.setdefault(x["source"], []).append(x["target"])
                elif typ == "achieves":
                    tactics_of.setdefault(x["source"], []).append(x["target"])
    for doc, title, key in (("tactics", "ATLAS tactics", "tactics"), ("techniques", "ATLAS techniques", "techniques"),
                            ("mitigations", "ATLAS mitigations", "mitigations")):
        w.document("atlas", doc, title, version=ver)
        for tid, t in d.get(key, {}).items():
            maps = []
            if key == "techniques":
                maps += [{"ns": "atlas", "id": m, "rel": "mitigated-by"} for m in mitig_of.get(tid, [])]
                maps += [{"ns": "atlas", "id": x, "rel": "tactic"} for x in tactics_of.get(tid, [])]
            if key == "mitigations":
                maps += [{"ns": "atlas", "id": x, "rel": "mitigates"} for x in mitigates.get(tid, [])]
            ar = t.get("attack-reference")
            if ar:
                maps.append({"ns": "attack", "id": ar.get("id") if isinstance(ar, dict) else ar, "rel": "same-as"})
            parent = tid.rsplit(".", 1)[0] if key == "techniques" and tid.count(".") == 2 else None
            w.item("atlas", doc, tid, t.get("name"), kind=key[:-1], parent=parent,
                   profiles=t.get("platforms") or t.get("categories") or [],
                   text={"description": t.get("description")},
                   refs=[f'{r.get("title")}: {r.get("url")}' for r in t.get("references") or [] if isinstance(r, dict)],
                   maps=maps, extra={"maturity": t.get("maturity"), "lifecycle": t.get("lifecycle-phases"),
                                     "modified": str(t.get("modified-date"))})
    return w.close()
