"""Разбор записей датасета: заголовок и текст из произвольного JSON, потоковое чтение JSONL/JSON-массивов
с байтовыми смещениями (по ним запись потом читается Range-запросом)."""
from __future__ import annotations

import codecs
import json
import re

TITLE_KEYS = ("title", "name", "question", "instruction", "prompt", "query", "scenario", "user", "input",
              "technique", "cve_id", "cve", "id")
SKIP_KEYS = {"system"}           # длинные повторяющиеся системные промпты
CONTENT_KEYS = {"value", "content", "text", "output", "response", "answer", "assistant", "gpt", "user", "input",
                "instruction", "question", "description"}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _first_turn(obj, role_keys=("human", "user")):
    for key in ("conversations", "messages"):
        turns = obj.get(key)
        if isinstance(turns, list):
            for t in turns:
                if isinstance(t, dict) and (t.get("from") or t.get("role")) in role_keys:
                    return t.get("value") or t.get("content")
    return None


def title_of(obj, fallback: str = "") -> str:
    t = None
    if isinstance(obj, dict):
        t = _first_turn(obj)
        if not t:
            for k in TITLE_KEYS:
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    t = v
                    break
    elif isinstance(obj, str):
        t = obj
    t = re.sub(r"\s+", " ", t or fallback).strip()
    return t[:200] + ("…" if len(t) > 200 else "")


def text_of(obj, limit: int = 30000) -> str:
    """Плоский текст записи для индекса и показа. Пропускает системные промпты."""
    out: list[str] = []
    size = 0

    def walk(x, key=None):
        nonlocal size
        if size > limit:
            return
        if isinstance(x, dict):
            if (x.get("from") or x.get("role")) == "system":
                return
            for k, v in x.items():
                if k in SKIP_KEYS:
                    continue
                walk(v, k)
        elif isinstance(x, list):
            for v in x:
                walk(v, key)
        elif x is not None and not isinstance(x, bool):
            s = str(x).strip()
            if not s:
                return
            line = s if (key is None or key in CONTENT_KEYS or len(s) > 120) else f"{key}: {s}"
            out.append(line)
            size += len(line) + 1

    walk(obj)
    return "\n".join(out)[:limit]


def cves_in(text: str) -> set[str]:
    return {c.upper() for c in CVE_RE.findall(text)}


def iter_jsonl(stream):
    """(offset, length, obj|None, raw) для каждой строки JSONL из байтового потока."""
    off = 0
    for line in stream:
        n = len(line)
        s = line.strip()
        if s:
            try:
                obj = json.loads(s)
            except ValueError:
                obj = None
            yield off, n, obj, s
        off += n


def iter_lines(stream):
    off = 0
    for line in stream:
        n = len(line)
        s = line.strip()
        if s:
            yield off, n, s.decode("utf-8", "replace")
        off += n


def iter_json_array(stream, chunk: int = 1 << 20):
    """Потоковый разбор JSON-массива верхнего уровня: (offset, length, obj) для каждого элемента.
    Смещения — в байтах исходного файла."""
    dec = json.JSONDecoder()
    udec = codecs.getincrementaldecoder("utf-8")("strict")
    buf, base, eof, started = "", 0, False, False  # base — байтовое смещение buf[0]

    def more():
        nonlocal buf, eof
        data = stream.read(chunk)
        if not data:
            eof = True
            buf += udec.decode(b"", final=True)
        else:
            buf += udec.decode(data)

    while True:
        i = 0
        while True:
            while i < len(buf) and buf[i] in " \t\r\n,":
                i += 1
            if i < len(buf) or eof:
                break
            more()
        if i >= len(buf):
            return
        if not started:
            if buf[i] != "[":
                raise ValueError("не JSON-массив")
            started = True
            base += len(buf[:i + 1].encode())
            buf = buf[i + 1:]
            continue
        if buf[i] == "]":
            return
        try:
            obj, end = dec.raw_decode(buf, i)
        except json.JSONDecodeError:
            if eof:
                raise
            more()
            continue
        start_b = base + len(buf[:i].encode())
        len_b = len(buf[i:end].encode())
        yield start_b, len_b, obj
        base = start_b + len_b
        buf = buf[end:]


def explode_json(obj):
    """Небольшой JSON-файл → записи с JSON-указателем (список ключей/индексов).
    Массив → элементы; объект со списками объектов → элементы этих списков; остальное — целиком."""
    if isinstance(obj, list):
        return [([i], x) for i, x in enumerate(obj)]
    if isinstance(obj, dict):
        out, rest = [], {}
        for k, v in obj.items():
            if isinstance(v, list) and v and all(isinstance(e, dict) for e in v):
                out += [([k, i], e) for i, e in enumerate(v)]
            elif isinstance(v, dict) and len(json.dumps(v, ensure_ascii=False)) > 1500:
                out.append(([k], v))
            else:
                rest[k] = v
        if rest:
            out.insert(0, ([], rest if out else obj))
        return out
    return [([], obj)]


def follow(obj, pointer):
    for p in pointer:
        obj = obj[p]
    return obj
