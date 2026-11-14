"""CISA Known Exploited Vulnerabilities (KEV) — уязвимости, эксплуатируемые в реальных атаках, со сроком
устранения и требуемым действием; FIRST EPSS — вероятность эксплуатации CVE в ближайшие 30 дней.
KEV: public domain (CISA). EPSS: свободно с указанием FIRST.
EPSS пишется не элементами каталога, а строками type=cve_score (таблица cve_scores)."""
from __future__ import annotations

import csv
import gzip
import io
import json
import os

from secreqs.catalog.model import RAW, Writer, fetch

KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# официальное зеркало CISA на GitHub: cisa.gov отвечает 403 части облачных адресов
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
SELF_NS = {"cisa-kev": "cve"}


def load() -> int:
    raw = os.path.join(RAW, "vulns")
    dest = os.path.join(raw, "kev.json")
    try:
        path = fetch(KEV, dest, max_age_days=1)
    except Exception:
        path = fetch(KEV_MIRROR, dest, max_age_days=1)
    kev = json.load(open(path, encoding="utf-8"))
    w = Writer("vulns")
    w.framework("cisa-kev", "CISA Known Exploited Vulnerabilities Catalog", "vulnerabilities", "CISA",
                "Public domain", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                version=kev.get("catalogVersion"), published=(kev.get("dateReleased") or "")[:10],
                description="CVE с подтверждённой эксплуатацией в реальных атаках: требуемое действие и срок "
                            "устранения для федеральных ведомств США, признак использования в атаках шифровальщиков.")
    w.document("cisa-kev", "kev", "KEV catalog", version=kev.get("catalogVersion"), date=(kev.get("dateReleased") or "")[:10])
    for v in kev["vulnerabilities"]:
        w.item("cisa-kev", "kev", v["cveID"], f'{v["vendorProject"]} {v["product"]}: {v["vulnerabilityName"]}',
               kind="exploited-vulnerability",
               severity="ransomware" if v.get("knownRansomwareCampaignUse") == "Known" else None,
               text={"description": v.get("shortDescription"), "fix": v.get("requiredAction"), "note": v.get("notes")},
               maps=[{"ns": "cwe", "id": c, "rel": "weakness"} for c in v.get("cwes") or []],
               extra={"vendor": v["vendorProject"], "product": v["product"], "date_added": v.get("dateAdded"),
                      "due_date": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse")})
    n = w.close()
    # EPSS → отдельный файл строк cve_score
    path = fetch(EPSS, os.path.join(raw, "epss_scores-current.csv.gz"), max_age_days=1)
    with gzip.open(path, "rt", encoding="utf-8") as f:
        head = f.readline().lstrip("#").strip()
        meta = dict(x.split(":", 1) for x in head.split(",") if ":" in x)
        rows = csv.DictReader(f)
        with open(os.path.join(os.path.dirname(w.path), "epss.jsonl"), "w", encoding="utf-8") as out:
            out.write(json.dumps({"type": "framework", "id": "epss", "title": "FIRST EPSS (Exploit Prediction Scoring System)",
                                  "kind": "vulnerabilities", "publisher": "FIRST", "license": "free with attribution",
                                  "url": "https://www.first.org/epss/", "version": meta.get("model_version"),
                                  "published": (meta.get("score_date") or "")[:10],
                                  "description": "Вероятность эксплуатации CVE в ближайшие 30 дней (0–1) и перцентиль."}) + "\n")
            k = 0
            for r in rows:
                out.write(json.dumps({"type": "cve_score", "cve": r["cve"], "source": "epss", "score": float(r["epss"]),
                                      "percentile": float(r["percentile"]), "date": (meta.get("score_date") or "")[:10]}) + "\n")
                k += 1
    return n + k
