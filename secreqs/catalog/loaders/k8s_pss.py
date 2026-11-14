"""Kubernetes Pod Security Standards (Privileged / Baseline / Restricted) из документации kubernetes.io:
контроль, требование, ограничиваемые поля и допустимые значения. CC BY 4.0 (The Kubernetes Authors)."""
from __future__ import annotations

import os
import re
from html import unescape

from secreqs.catalog.model import RAW, Writer, fetch

URL = "https://raw.githubusercontent.com/kubernetes/website/main/content/en/docs/concepts/security/pod-security-standards.md"
SELF_NS = {"k8s-pss": "k8s-pss"}


def strip(html):
    s = re.sub(r"\{\{<[^>]*>\}\}", "", html)
    s = re.sub(r"<li>", "\n- ", s)
    s = re.sub(r"<code>(.*?)</code>", r"`\1`", s, flags=re.S)
    s = re.sub(r"</p>|<br\s*/?>", "\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    return re.sub(r"[ \t]+", " ", unescape(s)).strip()


def load() -> int:
    md = open(fetch(URL, os.path.join(RAW, "k8s", "pod-security-standards.md"), max_age_days=30), encoding="utf-8").read()
    w = Writer("k8s_pss")
    w.framework("k8s-pss", "Kubernetes Pod Security Standards", "benchmark", "Kubernetes (SIG Auth)", "CC BY 4.0",
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                description="Три уровня политики безопасности подов: Privileged (без ограничений), Baseline (запрет "
                            "известных эскалаций привилегий) и Restricted (жёсткое укрепление). Применяются Pod Security "
                            "Admission (метка namespace pod-security.kubernetes.io/enforce=baseline|restricted).")
    for level in ("Baseline", "Restricted"):
        sec = re.search(rf"^### {level}\n(.+?)(?=^### |\Z)", md, re.S | re.M).group(1)
        intro = strip(sec.split("<table>")[0])
        w.document("k8s-pss", level.lower(), f"Pod Security Standards: {level}", description=intro)
        for row in re.findall(r"<tr>(.*?)</tr>", sec, re.S):
            tds = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
            if len(tds) < 2:
                continue
            control = strip(tds[0])
            body = strip(tds[1])
            desc, _, rest = body.partition("Restricted Fields")
            fields, _, allowed = rest.partition("Allowed Values")
            cid = f"{level.lower()}:{re.sub(r'[^a-z0-9]+', '-', control.lower()).strip('-')}"
            w.item("k8s-pss", level.lower(), cid, control, kind="control", severity=level,
                   text={"description": desc.strip(), "restricted_fields": fields.strip(),
                         "allowed_values": allowed.strip(),
                         "fix": f"Namespace label pod-security.kubernetes.io/enforce: {level.lower()}; "
                                f"pod spec must satisfy: {allowed.strip()[:500]}"})
    return w.close()
