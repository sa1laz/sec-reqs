#!/usr/bin/env python3
"""Разбор PDF CIS Benchmark в машиночитаемый вид.

  .venv/bin/python cis/parse_cis_pdf.py cis/pdf/27155.pdf [--id 27155] [--out cis/benchmarks]

На выходе каталог cis/benchmarks/<slug>/ с файлами:
  benchmark.json         метаданные, профили, дерево разделов с описаниями
  recommendations.jsonl  одна рекомендация на строку

Текстовые поля в Markdown: абзацы через пустую строку, блоки кода в ```,
строчный код в обратных кавычках. Переносы строк внутри блоков кода,
появившиеся из-за вёрстки PDF, склеиваются обратно.
"""
import argparse, json, os, re, sys
import pymupdf

FIELDS = {
    "Profile Applicability:": "profiles",
    "Description:": "description",
    "Rationale:": "rationale",
    "Rationale Statement:": "rationale",
    "Impact:": "impact",
    "Impact Statement:": "impact",
    "Audit:": "audit",
    "Audit Procedure:": "audit",
    "Remediation:": "remediation",
    "Remediation Procedure:": "remediation",
    "Default Value:": "default_value",
    "References:": "references",
    "Additional Information:": "additional_information",
    "CIS Controls:": "cis_controls",
    "MITRE ATT&CK Mappings:": "mitre_attack",
}
STATUS_RX = re.compile(r"^(?P<num>\d+(?:\.\d+)*)\s+(?P<title>.*?)\s*\((?P<st>Automated|Manual|Scored|Not Scored)\)\s*$", re.S)
SECTION_RX = re.compile(r"^(?P<num>\d+(?:\.\d+)*)\s+(?P<title>.+)$", re.S)
BULLET_RX = re.compile(r"^(?:[•●▪◦o\-–]\s+|\d{1,2}[.)]\s+|[a-z][.)]\s+)")
RIGHT = 531.0  # правая граница текстовой колонки в PDF CIS


def is_code_font(span):
    return "Courier" in span["font"] or "Mono" in span["font"] or "Consolas" in span["font"]


def is_bold(span):
    return "Bold" in span["font"] or bool(span["flags"] & 16)


def page_lines(page, pno):
    """Строки страницы в порядке чтения; каждая — список спанов."""
    spans = []
    for b in page.get_text("dict")["blocks"]:
        for l in b.get("lines", []):
            for s in l["spans"]:
                if s["text"] == "":
                    continue
                spans.append(s)
    spans.sort(key=lambda s: (round(s["origin"][1] / 3), s["bbox"][0]))
    lines, cur, cur_y = [], [], None
    for s in spans:
        y = s["origin"][1]
        if cur and abs(y - cur_y) > 3.0:
            lines.append(cur); cur = []
        if not cur:
            cur_y = y
        cur.append(s)
    if cur:
        lines.append(cur)
    out = []
    h = page.rect.height
    for sp in lines:
        sp.sort(key=lambda s: s["bbox"][0])
        text = "".join(s["text"] for s in sp)
        if not text.strip():
            continue
        y = sp[0]["origin"][1]
        if y > h - 50 and re.fullmatch(r"\s*Page \d+\s*", text):
            continue
        vis = [s for s in sp if s["text"].strip()]
        out.append({
            "page": pno, "y": y, "x0": min(s["bbox"][0] for s in vis), "x1": max(s["bbox"][2] for s in vis),
            "size": max(s["size"] for s in vis), "spans": sp, "text": text.strip(),
            "code": all(is_code_font(s) and s["size"] < 11 for s in vis),
            "bold": all(is_bold(s) for s in vis),
        })
    return out


def render_inline(line):
    """Текст строки с `строчным кодом`."""
    segs = []
    for s in line["spans"]:
        kind = is_code_font(s) and bool(s["text"].strip())
        if segs and (segs[-1][0] == kind or not s["text"].strip()):
            segs[-1][1] += s["text"]
        else:
            segs.append([kind, s["text"]])
    out = ""
    for kind, t in segs:
        if kind and "`" not in t:
            lead = t[: len(t) - len(t.lstrip())]
            trail = t[len(t.rstrip()):]
            out += f"{lead}`{t.strip()}`{trail}"
        else:
            out += t
    return re.sub(r"[ \t]+", " ", out).strip()


def render_code(lines):
    """Блок кода: склеить строки, перенесённые вёрсткой."""
    x_min = min(l["x0"] for l in lines)
    res = []
    carry = None  # (text, hard) — предыдущая строка ждёт продолжения
    for i, l in enumerate(lines):
        cw = l["size"] * 0.6
        raw = "".join(s["text"] for s in l["spans"]).rstrip("\n")
        indent = " " * max(0, round((l["x0"] - x_min) / cw)) if not raw.startswith(" ") else ""
        text = indent + raw.rstrip()
        if carry is not None:
            prev, glue = carry
            text = prev + glue + raw.strip()
        carry = None
        if i + 1 < len(lines):
            nxt = "".join(s["text"] for s in lines[i + 1]["spans"]).strip()
            tok = re.match(r"\S*?(?:-|\s|$)", nxt).group(0).rstrip() or nxt
            wrapped = l["x1"] + cw * (len(tok) + 0.5) > RIGHT and not raw.rstrip().endswith("\\")
            if wrapped:
                hard = l["x1"] > RIGHT - cw * 1.5
                glue = " " if raw != raw.rstrip() else ("" if (hard or raw.rstrip().endswith("-")) else " ")
                carry = (text, glue)
                continue
        res.append(text)
    if carry is not None:
        res.append(carry[0])
    return "```\n" + "\n".join(res) + "\n```"


def render_body(lines):
    """Тело поля в Markdown."""
    blocks, i = [], 0
    while i < len(lines):
        if lines[i]["code"]:
            j = i
            while j < len(lines) and lines[j]["code"]:
                j += 1
            blocks.append(render_code(lines[i:j]))
            i = j
            continue
        para, prev = [], None
        while i < len(lines) and not lines[i]["code"]:
            l = lines[i]
            t = render_inline(l)
            if l["bold"] and len(t) < 80:
                if para:
                    break
                para.append(f"**{t}**"); i += 1
                break
            if prev is not None:
                same_page = l["page"] == prev["page"]
                gap = (l["y"] - prev["y"]) if same_page else None
                brk = (
                    BULLET_RX.match(t)
                    or l["x0"] < prev["x0"] - 10 and not BULLET_RX.match(render_inline(prev))
                    or (gap is not None and gap > prev["size"] * 1.6)
                    or (gap is None and prev["x1"] < 430)
                )
                if brk:
                    break
            para.append(t)
            prev = l
            i += 1
        text = ""
        for t in para:
            if text and (text.endswith("-") and re.search(r"https?://\S*$", text) or re.search(r"https?://\S*[/=&?_]$", text)):
                text += t
            else:
                text += (" " if text else "") + t
        if text:
            blocks.append(text)
    # склеить пункты списков в один блок
    out = []
    for b in blocks:
        if out and BULLET_RX.match(b) and BULLET_RX.match(out[-1].split("\n")[-1]) and not out[-1].startswith("```"):
            out[-1] += "\n" + b
        else:
            out.append(b)
    return "\n\n".join(out).strip()


def parse_list(lines):
    body = render_body(lines)
    items = []
    for part in re.split(r"\n+", body):
        part = BULLET_RX.sub("", part.strip()).strip()
        if part:
            items.append(part)
    return items


def parse_controls(lines):
    """Таблица CIS Controls: версия, номер, название, описание, группы внедрения."""
    ig_x = {}
    for l in lines:
        for s in l["spans"]:
            m = re.fullmatch(r"\s*IG ?([123])\s*", s["text"])
            if m:
                ig_x[int(m.group(1))] = (s["bbox"][0] + s["bbox"][2]) / 2
        if not ig_x and re.search(r"IG ?1\s+IG ?2\s+IG ?3", l["text"]):
            sp = [s for s in l["spans"] if "IG" in s["text"]][-1]
            x0, x1 = sp["bbox"][0], sp["bbox"][2]
            full = sp["text"]
            for n in (1, 2, 3):
                k = re.search(rf"IG ?{n}", full)
                ig_x[n] = x0 + (x1 - x0) * ((k.start() + k.end()) / 2) / max(1, len(full))
    # Строка таблицы: строки названия (12pt), где-то среди них ячейка версии с отметками IG,
    # затем строки описания (9pt). Новая строка таблицы начинается с названия после описания.
    rows, cur = [], None

    def new_row():
        r = {"version": None, "control": None, "title": "", "description": "", "ig1": False, "ig2": False, "ig3": False}
        rows.append(r)
        return r

    for l in lines:
        if re.match(r"^(Controls?|Version)\b", l["text"]) and len(l["text"]) < 40 or re.search(r"IG ?1.*IG ?3", l["text"]):
            continue
        dots = [s for s in l["spans"] if s["text"].strip() in ("●", "•") and s["bbox"][0] > 380]
        rest = [s for s in l["spans"] if s not in dots and s["text"].strip()]
        ver = [s for s in rest if re.fullmatch(r"\s*v\d+(\.\d+)?\s*", s["text"]) and s["bbox"][0] < 150]
        rest = [s for s in rest if s not in ver]
        txt = re.sub(r"\s+", " ", "".join(s["text"] for s in rest)).strip()
        small = bool(rest) and max(s["size"] for s in rest) < 10.5
        if txt and not small:
            numbered = re.match(r"^\d+(\.\d+)*\s+\S", txt)
            if cur is None or cur["description"] or (numbered and cur["control"] and cur["version"]):
                cur = new_row()
        if cur is None:
            if not (ver or dots):
                continue
            cur = new_row()
        if ver:
            cur["version"] = ver[0]["text"].strip()
        for d in dots:
            if ig_x:
                xc = (d["bbox"][0] + d["bbox"][2]) / 2
                cur[f"ig{min(ig_x, key=lambda k: abs(ig_x[k] - xc))}"] = True
        if not txt:
            continue
        if small:
            cur["description"] = (cur["description"] + " " + txt).strip()
        else:
            m2 = re.match(r"^(\d+(?:\.\d+)*)\s+(.*)$", txt)
            if m2 and cur["control"] is None and not cur["title"]:
                cur["control"], txt = m2.group(1), m2.group(2)
            cur["title"] = (cur["title"] + ("" if cur["title"].endswith("-") else " ") + txt).strip()
    return rows


def find_start(lines, by_page, num, page, lo):
    """Индекс строки-заголовка с данным номером на странице page (1-based) или рядом."""
    for p in (page, page + 1, page - 1):
        for idx in by_page.get(p, []):
            if idx < lo:
                continue
            l = lines[idx]
            if l["bold"] and re.match(rf"^{re.escape(num)}(\s|$)", l["text"]):
                return idx
    return None


def slugify(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def parse(pdf_path, wb_id=None):
    doc = pymupdf.open(pdf_path)
    lines, by_page = [], {}
    for pno in range(len(doc)):
        for l in page_lines(doc[pno], pno + 1):
            by_page.setdefault(pno + 1, []).append(len(lines))
            lines.append(l)

    # заголовок документа с первой страницы
    first = " ".join(lines[i]["text"] for i in by_page.get(1, []))
    first = re.sub(r"\s+", " ", first)
    m = re.search(r"(CIS .*?Benchmark)\s*v?(\d+(?:\.\d+)+)\s*[-–—]\s*(\d{2}-\d{2}-\d{4})", first)
    title, version, date = (m.group(1), m.group(2), m.group(3)) if m else (first[:120], None, None)
    if date:
        mm, dd, yy = date.split("-"); date = f"{yy}-{mm}-{dd}"

    # Заголовки берём из вёрстки, а не из оглавления PDF: оно есть не во всех файлах.
    # Рекомендация — курсив 16pt, раздел — полужирный 14–16pt, оба начинаются с номера.
    def italic(l):
        return all("Italic" in s["font"] or s["flags"] & 2 for s in l["spans"] if s["text"].strip())

    start = next((i for i, l in enumerate(lines) if l["size"] >= 24 and l["text"] == "Recommendations"
                  and not (i and lines[i - 1]["text"].startswith("Appendix"))), None)
    if start is None:
        # Нет заголовка «Recommendations»: начинаем с первого раздела «1 …» после оглавления.
        start = next((i - 1 for i, l in enumerate(lines) if l["page"] > 3 and l["bold"] and l["size"] >= 15
                      and re.match(r"^1 \S", l["text"])), -1)
    entries, i, stop = [], start + 1, len(lines)
    while i < len(lines):
        l = lines[i]
        if entries and l["size"] >= 13.5 and l["bold"] and l["text"].startswith("Appendix"):
            stop = i
            break
        kind = None
        m0 = SECTION_RX.match(l["text"])
        if m0 and l["size"] >= 13.5:
            kind = "rec" if italic(l) and not l["bold"] and l["size"] >= 15 else ("section" if l["bold"] else None)
        elif m0 and l["bold"] and l["size"] >= 11.5 and l["x0"] < 80 and m0["num"].count(".") >= 2 \
                and entries and entries[-1]["num"].split(".")[0] == m0["num"].split(".")[0]:
            kind = "section"  # глубокие уровни разделов набраны 12–13pt
        if not kind:
            i += 1
            continue
        j, text = i + 1, l["text"]
        while j < len(lines) and lines[j]["page"] == l["page"] and abs(lines[j]["size"] - l["size"]) < 0.6 \
                and lines[j]["bold"] == l["bold"] and (italic(lines[j]) if kind == "rec" else True) \
                and not re.match(r"^\d+(\.\d+)+\s", lines[j]["text"]) and lines[j]["y"] - lines[j - 1]["y"] < l["size"] * 1.7 \
                and not (kind == "rec" and STATUS_RX.match(re.sub(r"\s+", " ", text))):
            text += " " + lines[j]["text"]
            j += 1
        text = re.sub(r"\s+", " ", text).strip()
        mr, ms = STATUS_RX.match(text), SECTION_RX.match(text)
        if kind == "rec":
            num, name, st = (mr["num"], mr["title"], mr["st"]) if mr else (ms["num"], ms["title"], None)
        else:
            num, name, st = ms["num"], ms["title"], None
        entries.append({"kind": kind, "num": num, "title": name, "status": st, "page": l["page"], "idx": i, "body": j})
        i = j
    for a, b in zip(entries, entries[1:] + [None]):
        a["end"] = b["idx"] if b else stop
    toc_recs = sum(1 for t in doc.get_toc() if STATUS_RX.match(re.sub(r"\s+", " ", t[1]).strip()))

    sections = {e["num"]: e for e in entries if e["kind"] == "section"}

    def path(num):
        parts, out = num.split("."), []
        for k in range(1, len(parts)):
            p = ".".join(parts[:k])
            if p in sections:
                out.append({"number": p, "title": sections[p]["title"]})
        return out

    def skip_title(seg):
        """Отбросить строки заголовка (жирные, до первого поля или обычного текста)."""
        k = 0
        while k < len(seg) and seg[k]["bold"] and seg[k]["text"] not in FIELDS:
            k += 1
        return seg[k:]

    recs, warnings = [], []
    for e in entries:
        if e["kind"] != "rec":
            continue
        if e["status"] is None:
            warnings.append(f"{e['num']}: в заголовке нет статуса проверки")
        seg = lines[e["body"]:e["end"]]
        buckets, cur = {}, None
        for l in seg:
            if l["bold"] and l["text"] in FIELDS:
                cur = FIELDS[l["text"]]
                buckets.setdefault(cur, [])
                continue
            if cur is None:
                continue
            buckets[cur].append(l)
        rec = {
            "uid": f"cis:{wb_id or slugify(title)}:{e['num']}",
            "benchmark_id": wb_id, "benchmark": title, "benchmark_version": version,
            "id": e["num"], "title": e["title"], "assessment_status": e["status"],
            "profiles": parse_list(buckets.get("profiles", [])),
            "section_path": path(e["num"]),
        }
        for f in ("description", "rationale", "impact", "audit", "remediation", "default_value", "additional_information"):
            rec[f] = render_body(buckets.get(f, [])) or None
        rec["references"] = parse_list(buckets.get("references", []))
        rec["cis_controls"] = parse_controls(buckets.get("cis_controls", []))
        mt = render_body(buckets.get("mitre_attack", []))
        rec["mitre_attack"] = mt or None
        rec["page_start"], rec["page_end"] = e["page"], lines[e["end"] - 1]["page"]
        for f in ("description", "audit", "remediation"):
            if not rec[f]:
                warnings.append(f"{e['num']}: пустое поле {f}")
        if not rec["profiles"]:
            warnings.append(f"{e['num']}: нет профиля")
        recs.append(rec)

    sec_out = []
    for e in entries:
        if e["kind"] != "section":
            continue
        desc = render_body(lines[e["body"]:e["end"]])
        sec_out.append({"number": e["num"], "title": e["title"], "level": e["num"].count(".") + 1,
                        "description": desc or None, "page": e["page"]})

    front, heads = {}, []
    names = ("Overview", "Target Technology Details", "Intended Audience", "Profile Definitions", "Summary")
    for k in range(start):
        if lines[k]["bold"] and lines[k]["size"] >= 13.5:
            heads.append(k)
    for a, b in zip(heads, heads[1:] + [start]):
        if lines[a]["text"] in names and lines[a]["page"] > 3:
            front[slugify(lines[a]["text"]).replace("-", "_")] = render_body(lines[a + 1:b]) or None
    meta = {
        "workbench_id": wb_id,
        "source_url": f"https://workbench.cisecurity.org/benchmarks/{wb_id}" if wb_id else None,
        "title": title, "version": version, "published": date,
        "license": "CC BY-NC-SA 4.0 (CIS Benchmarks, free PDF use); только для внутреннего некоммерческого использования",
        "source_file": os.path.basename(pdf_path), "pages": len(doc),
        "recommendations_in_pdf_outline": toc_recs or None, "recommendations_parsed": len(recs),
        "counts": {"automated": sum(r["assessment_status"] == "Automated" for r in recs),
                   "manual": sum(r["assessment_status"] == "Manual" for r in recs)},
        "front_matter": front, "sections": sec_out, "parse_warnings": warnings,
    }
    return meta, recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pdf", nargs="+")
    ap.add_argument("--id", type=int, help="ID бенчмарка в WorkBench (по умолчанию из имени файла)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmarks"))
    a = ap.parse_args()
    for pdf in a.pdf:
        stem = os.path.splitext(os.path.basename(pdf))[0]
        wb_id = a.id or (int(stem) if stem.isdigit() else None)
        meta, recs = parse(pdf, wb_id)
        slug = slugify(re.sub(r"^CIS ", "", meta["title"])) + (f"-v{meta['version']}" if meta["version"] else "")
        d = os.path.join(a.out, slug)
        os.makedirs(d, exist_ok=True)
        meta["slug"] = slug
        json.dump(meta, open(os.path.join(d, "benchmark.json"), "w"), ensure_ascii=False, indent=1)
        with open(os.path.join(d, "recommendations.jsonl"), "w") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"{slug}: {len(recs)} рекомендаций (в оглавлении PDF: {meta['recommendations_in_pdf_outline']}), "
              f"{len(meta['sections'])} разделов, предупреждений: {len(meta['parse_warnings'])}")
        for w in meta["parse_warnings"][:8]:
            print("   !", w)


if __name__ == "__main__":
    main()
