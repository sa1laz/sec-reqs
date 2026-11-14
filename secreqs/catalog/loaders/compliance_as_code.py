"""ComplianceAsCode (SCAP Security Guide): ~2500 правил для Linux, OpenShift, EKS и др. с описанием,
обоснованием, процедурой проверки (OCIL), шаблоном исправления и ссылками на NIST 800-53, CCI, SRG, STIG-ID,
CIS (по продуктам), PCI DSS, HIPAA, ISO 27001:2013, ANSSI, BSI, Essential Eight… Главный источник связей
«правило настройки ↔ требования стандартов». Лицензия BSD-3-Clause.
"""
from __future__ import annotations

import glob
import json
import os
import re
import tarfile
import urllib.request

import yaml

from secreqs.catalog.model import RAW, Writer, fetch, gh_headers

REPO = "ComplianceAsCode/content"
SELF_NS = {"cac": "cac-rule"}

# references → ns
REF_NS = {"nist": "nist-800-53", "disa": "cci", "srg": "srg", "pcidss": "pci-dss", "pcidss4": "pci-dss",
          "hipaa": "hipaa", "iso27001-2013": "iso27001-2013", "nist-csf": "nist-csf-1.1", "cui": "nist-800-171-r2",
          "ospp": "ospp", "anssi": "anssi", "ism": "ism", "cjis": "cjis", "bsi": "bsi", "ccn": "ccn", "e8": "e8"}


def latest():
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/latest", headers=gh_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.load(r)
    asset = next(a for a in d["assets"] if a["name"].endswith(".tar.bz2"))
    return d["tag_name"], d["published_at"][:10], asset["browser_download_url"], asset["name"]


def dejinja(s: str) -> str:
    """Убрать шаблоны Jinja из rule.yml так, чтобы остался валидный YAML."""
    s = re.sub(r"\{\{%.*?%\}\}", "", s, flags=re.S)
    s = re.sub(r"\{\{#.*?#\}\}", "", s, flags=re.S)
    # макрос целиком на отдельной строке верхнего уровня (complete_ocil_entry…) — убрать
    s = re.sub(r"^\{\{\{.*?\}\}\}\s*$", "", s, flags=re.M | re.S)

    def inline(m):
        body = m.group(1).strip()
        name = re.match(r"([\w.]+)", body)
        args = re.findall(r'"([^"]*)"', body)
        return f"<{name.group(1) if name else 'macro'}{(': ' + ', '.join(args)) if args else ''}>"
    return re.sub(r"\{\{\{(.*?)\}\}\}", inline, s, flags=re.S)


def html2text(s):
    if not s:
        return s
    s = re.sub(r"<pre>(.*?)</pre>", lambda m: "\n```\n" + m.group(1).strip() + "\n```\n", s, flags=re.S)
    s = re.sub(r"<tt>(.*?)</tt>|<code>(.*?)</code>", lambda m: "`" + (m.group(1) or m.group(2)) + "`", s, flags=re.S)
    s = re.sub(r"<br\s*/?>|</p>|<li>", "\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    return s.strip()


def split_refs(v):
    if isinstance(v, list):
        return [str(x).strip() for x in v]
    return [x.strip() for x in str(v).split(",") if x.strip()]


def walk_controls(ctrls, policy, product, out):
    for c in ctrls or []:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id", ""))
        for r in c.get("rules", []) or []:
            if isinstance(r, str) and "=" not in r:
                out.setdefault(r, []).append((policy, product, cid))
        walk_controls(c.get("controls"), policy, product, out)


def control_maps(root) -> dict[str, list]:
    """rule → [(policy_id, product, control_id)] из controls/*.yml (CIS, PCI DSS 4, STIG, ANSSI…)."""
    out: dict[str, list] = {}
    files = glob.glob(os.path.join(root, "controls", "*.yml")) + glob.glob(os.path.join(root, "products", "*", "controls", "*.yml"))
    for f in files:
        try:
            d = yaml.safe_load(dejinja(open(f, encoding="utf-8").read()))
        except Exception:
            continue
        if not isinstance(d, dict) or not d.get("id"):
            continue
        pid = d["id"]
        product = pid.split("_", 1)[1] if "_" in pid else None
        ctrls = list(d.get("controls") or [])
        sub = d.get("controls_dir")
        if sub:
            for sf in sorted(glob.glob(os.path.join(os.path.dirname(f), sub, "*.yml"))):
                try:
                    sd = yaml.safe_load(dejinja(open(sf, encoding="utf-8").read()))
                    ctrls += (sd or {}).get("controls") or []
                except Exception:
                    pass
        walk_controls(ctrls, pid, product, out)
    return out


def policy_ns(pid: str, product: str | None, cid: str):
    if pid.startswith("cis_"):
        return "cis-benchmark", f"{product}:{cid}"
    if pid.startswith("pcidss_4"):
        return "pci-dss", cid
    if pid.startswith("stig_"):
        return "stig-id", cid
    if pid.startswith("srg_"):
        return "srg", cid
    if pid.startswith("nist_"):
        return "nist-800-53", cid
    if pid == "hipaa":
        return "hipaa", cid
    if pid.startswith("pcidss_3"):
        return "pci-dss-3", cid
    base = re.sub(r"_.*", "", pid)
    return (base, cid) if base in ("anssi", "bsi", "ism", "e8", "ccn", "ospp") else None


def load() -> int:
    tag, date, url, name = latest()
    raw = os.path.join(RAW, "cac")
    arc = fetch(url, os.path.join(raw, name), max_age_days=60)
    src = os.path.join(raw, "src")
    root = os.path.join(src, name.replace(".tar.bz2", ""))
    if not os.path.isdir(root):
        with tarfile.open(arc) as t:
            t.extractall(src, filter="data")
    cmap = control_maps(root)
    w = Writer("compliance_as_code")
    w.framework("cac", "ComplianceAsCode / SCAP Security Guide rules", "benchmark", "ComplianceAsCode project",
                "BSD-3-Clause", f"https://github.com/{REPO}", version=tag, published=date,
                description="Правила проверки и исправления конфигурации (OVAL/Ansible/Bash) для RHEL, Ubuntu, SLES, "
                            "Debian, Amazon Linux, OpenShift, EKS и др. Каждое правило сопоставлено со множеством "
                            "стандартов — используется как мост между STIG, CIS, NIST 800-53, PCI DSS, HIPAA, ISO 27001.")
    w.document("cac", "rules", f"SCAP Security Guide {tag} rules", version=tag, date=date,
               url=f"https://github.com/{REPO}/releases/tag/{tag}")
    for f in sorted(glob.glob(os.path.join(root, "**", "rule.yml"), recursive=True)):
        rid = os.path.basename(os.path.dirname(f))
        src_text = open(f, encoding="utf-8").read()
        ocil_macro = re.search(r"^\{\{\{\s*(complete_ocil_entry\w*|ocil_\w+)\((.*?)\)\s*\}\}\}", src_text, re.M | re.S)
        try:
            d = yaml.safe_load(dejinja(src_text)) or {}
        except Exception:
            continue
        if ocil_macro and not d.get("ocil"):
            d["ocil"] = f"[{ocil_macro.group(1)}] " + re.sub(r"\s+", " ", ocil_macro.group(2))
        if not d.get("title"):
            continue
        refs = d.get("references") or {}
        products, maps = set(), []
        for k, v in refs.items():
            key, _, prod = str(k).partition("@")
            if prod:
                products.add(prod)
            if key == "cis" and prod:
                maps += [{"ns": "cis-benchmark", "id": f"{prod}:{x}", "rel": "implements"} for x in split_refs(v)]
            elif key == "stigid":
                maps += [{"ns": "stig-id", "id": x, "rel": "implements"} for x in split_refs(v)]
            elif key in REF_NS:
                maps += [{"ns": REF_NS[key], "id": re.sub(r"^Req-", "", x), "rel": "implements"} for x in split_refs(v)]
        for pid, prod, cid in cmap.get(rid, []):
            nt = policy_ns(pid, prod, cid)
            if not nt:
                continue
            maps.append({"ns": nt[0], "id": nt[1], "rel": "implements"})
            if prod and pid.startswith(("cis_", "stig_")):
                products.add(prod)
        for k in (d.get("identifiers") or {}):
            products.add(str(k).partition("@")[2])
        tpl = d.get("template") or {}
        rel_path = os.path.relpath(os.path.dirname(f), root)
        w.item("cac", "rules", rid, d["title"], kind="rule", parent=os.path.dirname(rel_path).replace(os.sep, " > "),
               severity=d.get("severity"), profiles=sorted(p for p in products if p),
               text={"description": html2text(d.get("description")), "rationale": html2text(d.get("rationale")),
                     "check": html2text(d.get("ocil")), "fix": html2text(d.get("fixtext")),
                     "warnings": html2text(json.dumps(d.get("warnings"), ensure_ascii=False)) if d.get("warnings") else None,
                     "srg_requirement": d.get("srg_requirement")},
               refs=[f"https://github.com/{REPO}/tree/{tag}/{rel_path}"], maps=maps,
               extra={"template": {"name": tpl.get("name"), "vars": tpl.get("vars")} if tpl else None,
                      "identifiers": d.get("identifiers")})
    return w.close()
