"""OWASP: ASVS 5.0 (требования к безопасности веб-приложений, уровни L1–L3), MASVS 2.1 (мобильные приложения),
Top 10 for LLM Applications 2025. CC BY-SA 4.0."""
from __future__ import annotations

import json
import os
import re
import urllib.request

import yaml

from secreqs.catalog.model import RAW, Writer, fetch, gh_headers

SELF_NS = {"owasp-asvs": "asvs", "owasp-masvs": "masvs", "owasp-llm": "owasp-llm"}
LLM_REPO = "OWASP/www-project-top-10-for-large-language-model-applications"
LLM_DIR = "2_0_vulns"


def release_asset(repo, suffix):
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=gh_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.load(r)
    a = next(a for a in d["assets"] if a["name"].endswith(suffix))
    return d["tag_name"], d["published_at"][:10], a["browser_download_url"], a["name"]


def asvs(w, raw):
    tag, date, url, name = release_asset("OWASP/ASVS", "_en.json")
    d = json.load(open(fetch(url, os.path.join(raw, name), max_age_days=30), encoding="utf-8"))
    ver = d.get("Version", "5.0.0")
    w.framework("owasp-asvs", f"OWASP Application Security Verification Standard {ver}", "controls", "OWASP",
                "CC BY-SA 4.0", "https://owasp.org/www-project-application-security-verification-standard/",
                version=ver, published=date, description=d.get("Description"))
    w.document("owasp-asvs", "asvs", f'{d.get("Name", "ASVS")} {ver}', version=ver, date=date)
    for ch in d["Requirements"]:
        for sec in ch.get("Items", []):
            for r in sec.get("Items", []):
                lvl = r.get("L")
                w.item("owasp-asvs", "asvs", r["Shortcode"], r["Description"][:200], kind="requirement",
                       parent=f'{ch["Shortcode"]} {ch["Name"]} > {sec["Shortcode"]} {sec["Name"]}',
                       severity=f"L{lvl}" if lvl else None,
                       profiles=[f"L{i}" for i in range(int(lvl), 4)] if str(lvl).isdigit() else [],
                       text={"description": r["Description"]})


def masvs(w, raw):
    tag, date, url, name = release_asset("OWASP/masvs", ".yaml")
    d = yaml.safe_load(open(fetch(url, os.path.join(raw, name), max_age_days=60), encoding="utf-8"))
    ver = d["metadata"].get("version", tag)
    w.framework("owasp-masvs", "OWASP Mobile Application Security Verification Standard", "controls", "OWASP",
                "CC BY-SA 4.0", "https://mas.owasp.org/MASVS/", version=ver, published=date,
                description=d["metadata"].get("remarks"))
    w.document("owasp-masvs", "masvs", f"MASVS {ver}", version=ver, date=date)
    for g in d["groups"]:
        for c in g.get("controls", []):
            w.item("owasp-masvs", "masvs", c["id"], c["statement"], kind="control", parent=f'{g["id"]} {g["title"]}',
                   text={"description": c.get("description"), "section": (g.get("description") or "").strip()})


def llm(w, raw):
    req = urllib.request.Request(f"https://api.github.com/repos/{LLM_REPO}/contents/{LLM_DIR}", headers=gh_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        files = [x["name"] for x in json.load(r) if re.match(r"LLM\d\d_.+\.md$", x["name"]) and not x["name"].startswith("LLM00")]
    w.framework("owasp-llm", "OWASP Top 10 for LLM Applications 2025", "threats", "OWASP GenAI Security Project",
                "CC BY-SA 4.0", "https://genai.owasp.org/llm-top-10/", version="2025",
                description="Десять главных рисков приложений на LLM с описанием, мерами защиты и сценариями атак.")
    w.document("owasp-llm", "top10-2025", "OWASP Top 10 for LLM Applications 2025", version="2025")
    for name in sorted(files):
        md = open(fetch(f"https://raw.githubusercontent.com/{LLM_REPO}/main/{LLM_DIR}/{name}",
                        os.path.join(raw, "llm", name), max_age_days=30), encoding="utf-8").read()
        m = re.search(r"^##\s*(LLM\d\d):?\s*\d*\s*(.+)$", md, re.M)
        if not m:
            continue

        def sec(title):
            s = re.search(rf"^###\s*{title}.*?\n(.+?)(?=^### |\Z)", md, re.S | re.M | re.I)
            return s.group(1).strip() if s else None
        refs = re.findall(r"\[([^\]]+)\]\((https?://[^)]+)\)", sec("Reference") or "")
        maps = [{"ns": "atlas", "id": x, "rel": "related"} for x in sorted(set(re.findall(r"AML\.T\d{4}(?:\.\d{3})?", md)))]
        maps += [{"ns": "cwe", "id": x, "rel": "related"} for x in sorted(set(re.findall(r"CWE-\d+", md)))]
        w.item("owasp-llm", "top10-2025", m.group(1), m.group(2).strip(), kind="risk",
               text={"description": sec("Description"), "fix": sec("Prevention and Mitigation"),
                     "examples": sec("Example Attack Scenarios") or sec("Common Examples")},
               refs=[f"{a}: {u}" for a, u in refs], maps=maps)


def load() -> int:
    raw = os.path.join(RAW, "owasp")
    w = Writer("owasp")
    asvs(w, raw)
    masvs(w, raw)
    llm(w, raw)
    return w.close()
