"""Prowler: ~1700 автоматических проверок облаков и SaaS (AWS, Azure, GCP, Kubernetes, M365, Google Workspace,
GitHub, Okta…) с описанием риска и исправлением (CLI, Terraform, CloudFormation), и ~110 файлов соответствия
(ISO 27001, NIST 800-53/CSF/171, PCI DSS, SOC 2, HIPAA, GDPR, NIS2, C5, ENS, MITRE ATT&CK, CIS Controls,
CSA CCM, CIS Benchmarks…), где требования стандартов связаны с проверками. Лицензия Apache-2.0.
"""
from __future__ import annotations

import glob
import json
import os
import re
import tarfile
import urllib.request

from secreqs.catalog.model import RAW, Writer, fetch, gh_headers

REPO = "prowler-cloud/prowler"
SELF_NS = {"prowler": "prowler-check"}

# стем файла соответствия (без _<provider>) → ns, нормализатор id
NS_BY_STEM = [
    (r"^nist_800_53_revision_5$", "nist-800-53"), (r"^nist_800_53_revision_4$", "nist-800-53-r4"),
    (r"^nist_csf_2\.0$", "nist-csf-2"), (r"^nist_csf_1\.1$", "nist-csf-1.1"),
    (r"^nist_800_171_revision_2$", "nist-800-171-r2"), (r"^iso27001_2022$", "iso27001"),
    (r"^iso27001_2013$", "iso27001-2013"), (r"^pci_4\.0$", "pci-dss"), (r"^pci_3\.2\.1$", "pci-dss-3"),
    (r"^mitre_attack$", "attack"), (r"^hipaa$", "hipaa"), (r"^gdpr$", "gdpr"), (r"^soc2$", "soc2"),
    (r"^cis_controls_8\.1$", "cis-controls-v8"), (r"^csa_ccm_4\.0$", "csa-ccm"), (r"^nis2$", "nis2"),
    (r"^c5$", "c5"), (r"^ens_rd2022$", "ens"), (r"^asd_essential_eight$", "e8"), (r"^cisa_scuba", "scuba-policy"),
]


def latest():
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/latest", headers=gh_headers())
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["tag_name"]


def g(d, *keys):
    for k in keys:
        for kk in (k, k.lower(), k[:1].lower() + k[1:]):
            if kk in d:
                return d[kk]
    return None


def stem_of(fname, provider):
    s = os.path.basename(fname)[:-5]
    return s[: -len(provider) - 1] if provider and s.endswith("_" + provider) else s


def ns_for(stem):
    for rx, ns in NS_BY_STEM:
        if re.search(rx, stem):
            return ns
    if stem.startswith("cis_"):
        return "cis-benchmark"
    return None


def req_alias(ns, stem, provider, rid, name):
    if not ns:
        return None
    if ns in ("nist-800-53", "nist-800-53-r4"):
        return name or rid
    if ns == "nist-csf-2" and name:
        m = re.match(r"([A-Z]{2}\.[A-Z]{2})-(\d+)", name)
        return f"{m.group(1)}-{int(m.group(2)):02d}" if m else name
    if ns == "nist-csf-1.1":
        return name or rid
    if ns == "cis-benchmark":
        return f"{provider} {stem[4:]}:{rid}"
    return rid


def attrs_text(attrs):
    if isinstance(attrs, dict):
        attrs = [attrs]
    lines = []
    for a in attrs or []:
        for k, v in (a or {}).items():
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (list, dict)):
                v = json.dumps(v, ensure_ascii=False)
            lines.append(f"{k}: {v}")
    return "\n".join(lines)


def load() -> int:
    tag = latest()
    raw = os.path.join(RAW, "prowler")
    arc = fetch(f"https://codeload.github.com/{REPO}/tar.gz/refs/tags/{tag}", os.path.join(raw, f"prowler-{tag}.tar.gz"),
                max_age_days=30)
    root = os.path.join(raw, "src", f"prowler-{tag}")
    if not os.path.isdir(os.path.join(root, "prowler", "compliance")):
        with tarfile.open(arc) as t:
            members = [m for m in t.getmembers() if "/prowler/compliance/" in m.name or m.name.endswith(".metadata.json")]
            t.extractall(os.path.join(raw, "src"), members=members, filter="data")
    w = Writer("prowler")
    # 1) соответствия: требования стандартов → проверки
    w.framework("prowler-compliance", "Prowler compliance mappings", "crosswalk", "Prowler", "Apache-2.0",
                f"https://github.com/{REPO}/tree/{tag}/prowler/compliance", version=tag,
                description="Требования стандартов (ISO 27001, NIST, PCI DSS, SOC 2, HIPAA, GDPR, NIS2, C5, CIS…) в разрезе "
                            "провайдеров с перечнем автоматических проверок Prowler, которые их покрывают.")
    check_maps: dict[str, list] = {}
    for f in sorted(glob.glob(os.path.join(root, "prowler", "compliance", "**", "*.json"), recursive=True)):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        reqs = g(d, "Requirements")
        if not reqs:
            continue
        provider = g(d, "Provider") or (os.path.basename(os.path.dirname(f)) if os.path.basename(os.path.dirname(f)) != "compliance" else "multi")
        provider = str(provider).lower()
        stem = stem_of(f, provider)
        ns = ns_for(stem)
        doc = os.path.basename(f)[:-5]
        w.document("prowler-compliance", doc, f'{g(d, "Name") or g(d, "Framework")} ({provider})',
                   version=str(g(d, "Version") or ""), url=f"https://github.com/{REPO}/blob/{tag}/" + os.path.relpath(f, root),
                   description=g(d, "Description"), extra={"provider": provider, "framework_ns": ns, "stem": stem})
        for r in reqs:
            rid = str(g(r, "Id"))
            name = g(r, "Name")
            checks = g(r, "Checks") or []
            if isinstance(checks, dict):
                checks = sorted({c for v in checks.values() for c in (v or [])})
            alias = req_alias(ns, stem, provider, rid, name)
            maps = [{"ns": "prowler-check", "id": c, "rel": "checked-by"} for c in checks]
            if ns == "nist-800-53" and alias:
                maps.append({"ns": "nist-800-53", "id": alias, "rel": "is"})
            w.item("prowler-compliance", doc, rid, (name if name and name != rid else None) or (g(r, "Description") or rid)[:200],
                   kind="requirement", parent=(g(r, "Attributes") or [{}])[0].get("Section") if isinstance(g(r, "Attributes"), list) else (g(r, "Attributes") or {}).get("Section"),
                   text={"description": g(r, "Description"), "attributes": attrs_text(g(r, "Attributes"))},
                   maps=maps, extra={"checks": checks, "aliases": [{"ns": ns, "id": alias}] if ns and alias else []})
            for c in checks:
                if ns and alias:
                    check_maps.setdefault(c, []).append({"ns": ns, "id": alias, "rel": "supports"})
    # 2) проверки
    w.framework("prowler", "Prowler checks", "benchmark", "Prowler", "Apache-2.0", f"https://github.com/{REPO}",
                version=tag, description="Автоматические проверки безопасности облаков и SaaS с риском и исправлением; "
                                         "maps показывает требования стандартов, которые проверка помогает подтвердить.")
    by_provider: dict[str, list] = {}
    for f in glob.glob(os.path.join(root, "prowler", "providers", "**", "*.metadata.json"), recursive=True):
        try:
            m = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        by_provider.setdefault(str(m.get("Provider", "other")).lower(), []).append(m)
    for prov, checks in sorted(by_provider.items()):
        w.document("prowler", prov, f"Prowler checks: {prov}", version=tag)
        for m in sorted(checks, key=lambda x: x["CheckID"]):
            rem = m.get("Remediation") or {}
            code = rem.get("Code") or {}
            rec = rem.get("Recommendation") or {}
            w.item("prowler", prov, m["CheckID"], m.get("CheckTitle") or m["CheckID"], kind="check",
                   parent=m.get("ServiceName"), severity=m.get("Severity"), profiles=m.get("Categories") or [],
                   text={"description": m.get("Description"), "risk": m.get("Risk"), "fix": rec.get("Text"),
                         "fix_cli": code.get("CLI"), "fix_terraform": code.get("Terraform"),
                         "fix_iac": code.get("NativeIaC"), "fix_other": code.get("Other"), "note": m.get("Notes")},
                   refs=[u for u in [m.get("RelatedUrl"), rec.get("Url")] + (m.get("AdditionalURLs") or []) if u],
                   maps=check_maps.get(m["CheckID"], []),
                   extra={"resource_type": m.get("ResourceType"), "related_checks": m.get("RelatedTo") or []})
    return w.close()
