"""Библиотека политик Kyverno (kyverno/policies): готовые политики Kubernetes для admission/аудита —
Pod Security, best practices, мультиарендность, supply chain, сеть… У политики есть название, категория,
критичность, описание и сам YAML (его можно применить в кластере). Apache-2.0."""
from __future__ import annotations

import glob
import os
import re
import tarfile

import yaml

from secreqs.catalog.model import RAW, Writer, fetch

URL = "https://codeload.github.com/kyverno/policies/tar.gz/refs/heads/main"
SELF_NS = {"kyverno": "kyverno-policy"}
A = "policies.kyverno.io/"


def load() -> int:
    raw = os.path.join(RAW, "kyverno")
    arc = fetch(URL, os.path.join(raw, "policies-main.tar.gz"), max_age_days=14)
    src = os.path.join(raw, "src")
    if not os.path.isdir(src):
        with tarfile.open(arc) as t:
            t.extractall(src, filter="data")
    root = glob.glob(os.path.join(src, "*"))[0]
    w = Writer("kyverno")
    w.framework("kyverno", "Kyverno policy library", "policies", "Kyverno (CNCF)", "Apache-2.0",
                "https://kyverno.io/policies/",
                description="Готовые политики Kubernetes (Kyverno ClusterPolicy / ValidatingPolicy …): проверка и "
                            "исправление манифестов при admission и фоновый аудит. Поле fix содержит YAML политики.")
    seen, docs = {}, set()
    for f in sorted(glob.glob(os.path.join(root, "**", "*.yaml"), recursive=True)):
        rel = os.path.relpath(f, root)
        if any(p.startswith((".", "_")) for p in rel.split(os.sep)) or "/.chainsaw" in rel or "chainsaw" in rel \
                or os.path.basename(f) in ("kustomization.yaml", "artifacthub-pkg.yml"):
            continue
        try:
            docs_y = list(yaml.safe_load_all(open(f, encoding="utf-8")))
        except Exception:
            continue
        for d in docs_y:
            if not isinstance(d, dict) or "kyverno.io" not in str(d.get("apiVersion", "")) \
                    and "policies.kyverno.io" not in str(d.get("apiVersion", "")):
                continue
            md = d.get("metadata") or {}
            ann = md.get("annotations") or {}
            title = ann.get(A + "title")
            if not title:
                continue
            name = md.get("name")
            variant = rel.split(os.sep)[0]
            key = name
            if key in seen:
                seen[key].append(f'{d.get("kind")} ({variant})')
                continue
            seen[key] = [f'{d.get("kind")} ({variant})']
            cat = (ann.get(A + "category") or "Other").split(",")[0].strip()
            doc = re.sub(r"[^a-z0-9]+", "-", cat.lower()).strip("-")
            if doc not in docs:
                docs.add(doc)
                w.document("kyverno", doc, f"Kyverno policies: {cat}")
            body = yaml.safe_dump(d, sort_keys=False, allow_unicode=True)
            w.item("kyverno", doc, name, title, kind="policy", parent=ann.get(A + "subject"),
                   severity=ann.get(A + "severity"), profiles=[d.get("kind")],
                   text={"description": ann.get(A + "description"), "fix": body[:12000]},
                   refs=[f"https://github.com/kyverno/policies/blob/main/{rel}"],
                   extra={"minversion": ann.get(A + "minversion"), "variants": seen[key],
                          "category": ann.get(A + "category")})
    return w.close()
