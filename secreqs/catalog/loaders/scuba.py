"""CISA SCuBA Secure Configuration Baselines: Google Workspace (ScubaGoggles) и Microsoft 365 (ScubaGear).

Политика: ID (GWS.GMAIL.2.1v1), формулировка с SHALL/SHOULD, обоснование, примечание, связи с NIST 800-53
и MITRE ATT&CK, инструкция по настройке, признак автоматической проверки. Public domain (CISA).
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

from secreqs.catalog.model import RAW, Writer, fetch, gh_headers

REPOS = [
    # (repo, путь к baselines, префикс документа, продукт)
    ("cisagov/ScubaGoggles", "scubagoggles/baselines", "gws", "Google Workspace"),
    ("cisagov/ScubaGear", "PowerShell/ScubaGear/baselines", "m365", "Microsoft 365"),
]
SKIP = {"README.md", "removedpolicies.md"}


def latest_tag(repo):
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=gh_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.load(r)
    return d["tag_name"], d["published_at"][:10]


def list_md(repo, path, ref):
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/contents/{path}?ref={ref}", headers=gh_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        return [x["name"] for x in json.load(r) if x["name"].endswith(".md") and x["name"] not in SKIP]


def bullet(block, label):
    m = re.search(rf"^- _{re.escape(label)}:?_:?\s*(.+?)(?=^\s*- |\Z)", block, re.M | re.S)
    return m.group(1).strip() if m else None


def parse(md: str):
    title = re.search(r"^# (.+)$", md, re.M).group(1).strip()
    intro = md.split("\n#", 1)[0]
    sections = re.split(r"^## (\d+)\. (.+)$", md, flags=re.M)
    out = []
    for i in range(1, len(sections) - 2, 3):
        num, stitle, body = sections[i], sections[i + 1].strip(), sections[i + 2]
        sec_desc = body.split("###", 1)[0].strip()
        resources = re.findall(r"\[([^\]]+)\]\((https?://[^)]+)\)", (re.search(r"### Resources(.+?)(?=^### |\Z)", body, re.S | re.M) or [None, ""])[1])
        impl = {m.group(1): m.group(2).strip() for m in re.finditer(
            r"^#### (\S+?) Instructions\s*\n(.+?)(?=^#### |^## |\Z)", body, re.M | re.S)}
        pol_part = (re.search(r"### Policies(.+?)(?=^### (?!#)|\Z)", body, re.S | re.M) or [None, ""])[1]
        for m in re.finditer(r"^#### (\S+)\s*\n(.+?)(?=^#### |\Z)", pol_part, re.M | re.S):
            pid, block = m.group(1), m.group(2)
            statement = block.strip().split("\n\n", 1)[0].strip()
            # policy text may continue with sub-bullets before badges
            lines = []
            for ln in block.strip().splitlines():
                if ln.startswith("[![") or ln.startswith("- _"):
                    break
                lines.append(ln)
            statement = "\n".join(lines).strip() or statement
            badges = re.findall(r"badge/([A-Za-z_]+)-", block)
            nist = bullet(block, "NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping") or ""
            ttps = sorted(set(re.findall(r"attack\.mitre\.org/techniques/(T\d{4})/(?:(\d{3})/)?", block)))
            level = "SHALL" if re.search(r"\b(SHALL|MUST)\b", statement) and not re.search(r"\b(SHALL|MUST) NOT\b|\bSHOULD\b", statement) else \
                    "SHALL NOT" if re.search(r"\b(SHALL|MUST) NOT\b", statement) else "SHOULD"
            out.append({
                "id": pid, "title": re.sub(r"\s+", " ", statement)[:300], "section": f"{num}. {stitle}",
                "section_desc": sec_desc, "statement": statement, "level": level, "badges": badges,
                "rationale": bullet(block, "Rationale"), "note": bullet(block, "Note"),
                "last_modified": bullet(block, "Last modified"),
                "nist": [n.strip() for n in re.split(r",\s*", nist) if re.match(r"[A-Z]{2}-\d", n.strip())],
                "ttps": [t + (f".{s}" if s else "") for t, s in ttps], "fix": impl.get(pid),
                "resources": [f"{a}: {u}" for a, u in resources],
            })
    return title, intro.split("\n", 1)[-1].strip(), out


def load() -> int:
    w = Writer("scuba")
    w.framework("scuba", "CISA SCuBA Secure Configuration Baselines", "benchmark", "CISA", "Public domain (CC0)",
                "https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project",
                description="Базовые настройки безопасности облачных офисных платформ: Google Workspace "
                            "(ScubaGoggles) и Microsoft 365 (ScubaGear). SHALL — обязательно, SHOULD — рекомендуется. "
                            "Политики с меткой Automated_Check проверяются утилитами ScubaGoggles/ScubaGear.")
    for repo, path, prefix, product in REPOS:
        tag, date = latest_tag(repo)
        for name in list_md(repo, path, tag):
            raw = fetch(f"https://raw.githubusercontent.com/{repo}/{tag}/{path}/{name}",
                        os.path.join(RAW, "scuba", prefix, tag, name), max_age_days=30)
            title, intro, pols = parse(open(raw, encoding="utf-8").read())
            if not pols:
                continue
            doc = f"{prefix}-{name[:-3]}"
            w.document("scuba", doc, title, version=tag, date=date,
                       url=f"https://github.com/{repo}/blob/{tag}/{path}/{name}", description=intro[:3000],
                       extra={"product": product})
            for p in pols:
                maps = [{"ns": "nist-800-53", "id": n, "rel": "maps-to"} for n in p["nist"]]
                maps += [{"ns": "attack", "id": t, "rel": "mitigates"} for t in p["ttps"]]
                w.item("scuba", doc, p["id"], p["title"], kind="policy", parent=p["section"],
                       severity=p["level"], profiles=p["badges"],
                       text={"description": p["statement"], "rationale": p["rationale"], "note": p["note"],
                             "fix": p["fix"], "section": p["section_desc"]},
                       refs=p["resources"], maps=maps,
                       extra={"last_modified": p["last_modified"], "automated_check": "Automated_Check" in p["badges"]})
    return w.close()
