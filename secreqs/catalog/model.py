"""Общие функции загрузчиков: скачивание с кешем, нормализация идентификаторов, запись JSONL."""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request

from secreqs.core import DATA

RAW = os.path.join(DATA, "raw")
OUT = os.path.join(DATA, "catalog")
UA = "Mozilla/5.0 (sec-reqs catalog builder)"

# Пространства имён для связей между стандартами
NS = {
    "nist-800-53": "NIST SP 800-53 rev5, id вида ac-2 / ac-2.1",
    "nist-csf-2": "NIST CSF 2.0, id вида PR.AA-01",
    "nist-ssdf": "NIST SP 800-218 SSDF, id вида PO.1.1",
    "cci": "DISA Control Correlation Identifier, CCI-000366",
    "srg": "DISA SRG requirement, SRG-OS-000480-GPOS-00227",
    "stig": "STIG rule, V-257777",
    "cis-controls-v8": "CIS Controls v8, 4.1",
    "cis-controls-v7": "CIS Controls v7.1",
    "cis-benchmark": "рекомендация CIS Benchmark: <продукт>:<номер>",
    "attack": "MITRE ATT&CK, T1078 / T1078.001 / M1032 / TA0001",
    "d3fend": "MITRE D3FEND, D3-MFA",
    "atlas": "MITRE ATLAS, AML.T0051",
    "cwe": "CWE-79", "capec": "CAPEC-66", "cve": "CVE-2024-3094",
    "pci-dss": "PCI DSS, 8.3.1", "iso27001": "ISO/IEC 27001:2022 Annex A, A.5.15",
    "hipaa": "HIPAA, 164.312(a)(1)", "asvs": "OWASP ASVS 5.0, V6.2.1",
    "owasp-top10": "OWASP Top 10", "soc2": "SOC 2 TSC, CC6.1", "gdpr": "GDPR article",
}


def norm_ref(ns: str, ident: str) -> str:
    s = str(ident).strip()
    if ns == "nist-800-53":
        # "AC-2 (1)", "AC-2(1)", "ac-2.1", "AC-02(01)" → "ac-2.1"
        m = re.match(r"(?i)^\s*([a-z]{2})-0*(\d+)\s*(?:\(\s*0*(\d+)\s*\)|\.0*(\d+))?", s)
        if m:
            fam, n, e1, e2 = m.groups()
            return f"{fam.lower()}-{int(n)}" + (f".{int(e1 or e2)}" if (e1 or e2) else "")
        return s.lower()
    if ns == "nist-csf-2":
        m = re.match(r"(?i)^([a-z]{2}\.[a-z]{2})-0*(\d+)$", s)
        return f"{m.group(1).upper()}-{int(m.group(2)):02d}" if m else s.upper()
    if ns in ("cwe", "capec", "cve", "cci"):
        p = ns.upper()
        s = s.upper()
        return s if s.startswith(p + "-") else f"{p}-{s}"
    if ns in ("attack", "atlas", "d3fend", "nist-ssdf", "srg", "stig"):
        return s.upper() if ns != "d3fend" else s
    return s


def fetch(url: str, dest: str, max_age_days: float = 7, headers: dict | None = None) -> str:
    """Скачать url в dest, если файла нет или он старше max_age_days. Возвращает путь."""
    if os.path.exists(dest) and time.time() - os.path.getmtime(dest) < max_age_days * 86400:
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    tmp = dest + ".part"
    with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
    os.replace(tmp, dest)
    return dest


def fetch_json(url: str, dest: str, **kw):
    return json.load(open(fetch(url, dest, **kw), encoding="utf-8"))


def gh_headers() -> dict:
    """Заголовки для GitHub API (токен из GITHUB_TOKEN повышает лимит запросов)."""
    t = os.environ.get("GITHUB_TOKEN")
    return {"Authorization": f"Bearer {t}"} if t else {}


def clean(s) -> str | None:
    if s is None:
        return None
    s = re.sub(r"[ \t]+\n", "\n", str(s)).strip()
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s or None


class Writer:
    """Пишет JSONL одного загрузчика; считает элементы по документам."""

    def __init__(self, name: str):
        os.makedirs(OUT, exist_ok=True)
        self.path = os.path.join(OUT, f"{name}.jsonl")
        self.f = open(self.path + ".part", "w", encoding="utf-8")
        self.n = 0

    def _w(self, rec):
        self.f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def framework(self, id, title, kind, publisher, license, url, version=None, published=None, description=None):
        self._w({"type": "framework", "id": id, "title": title, "kind": kind, "publisher": publisher,
                 "license": license, "url": url, "version": version, "published": published,
                 "description": clean(description)})

    def document(self, framework, id, title, version=None, date=None, url=None, description=None, extra=None):
        self._w({"type": "document", "framework": framework, "id": id, "title": title, "version": version,
                 "date": date, "url": url, "description": clean(description), "extra": extra or {}})

    def item(self, framework, document, id, title, kind="requirement", parent=None, severity=None,
             profiles=None, text=None, refs=None, maps=None, extra=None):
        text = {k: clean(v) for k, v in (text or {}).items() if clean(v)}
        maps = [{"ns": m["ns"], "id": norm_ref(m["ns"], m["id"]), "rel": m.get("rel", "related")}
                for m in (maps or []) if m.get("id")]
        uniq = {(m["ns"], m["id"], m["rel"]): m for m in maps}
        self._w({"type": "item", "framework": framework, "document": document, "id": str(id),
                 "title": clean(title) or str(id), "kind": kind, "parent": parent, "severity": severity,
                 "profiles": profiles or [], "text": text, "refs": refs or [], "maps": list(uniq.values()),
                 "extra": extra or {}})
        self.n += 1

    def close(self):
        self.f.close()
        os.replace(self.path + ".part", self.path)
        return self.n
