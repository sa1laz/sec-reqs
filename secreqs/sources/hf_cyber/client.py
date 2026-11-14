"""HTTP-доступ к датасету на Hugging Face Hub без скачивания: Range-запросы и потоковое чтение.

Токен: переменная окружения HF_TOKEN или строка HF_TOKEN=… в .env в корне репозитория.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict

from secreqs.core import DATA, ROOT

REPO = os.environ.get("HF_DATASET", "Vyber07/cyber-security")
REVISION = os.environ.get("HF_REVISION", "main")
FILES_CACHE = os.path.join(DATA, "hf_cyber_files.json")
DB = os.environ.get("HF_CYBER_DB", os.path.join(DATA, "hf_cyber.db"))
UA = "sec-reqs-mcp/0.2"


def token() -> str | None:
    t = os.environ.get("HF_TOKEN")
    if t:
        return t.strip()
    env = os.path.join(ROOT, ".env")
    if os.path.exists(env):
        for line in open(env):
            if line.startswith("HF_TOKEN="):
                return line.split("=", 1)[1].strip().strip("'\"")
    return None


def _req(url: str, headers: dict | None = None, timeout: float = 60):
    h = {"User-Agent": UA, **(headers or {})}
    t = token()
    if t:
        h["Authorization"] = "Bearer " + t
    last = None
    for attempt in range(3):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404):
                raise
            last = e
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
        time.sleep(1.5 * (attempt + 1))
    raise last


def file_url(path: str) -> str:
    return f"https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/" + urllib.parse.quote(path)


def open_stream(path: str, start: int = 0, timeout: float = 120):
    return _req(file_url(path), {"Range": f"bytes={start}-"} if start else None, timeout)


def read_range(path: str, offset: int, length: int) -> bytes:
    if length <= 0:
        return b""
    r = _req(file_url(path), {"Range": f"bytes={offset}-{offset + length - 1}"})
    data = r.read()
    if r.status == 200 and offset:  # сервер проигнорировал Range
        data = data[offset:offset + length]
    return data[:length]


# Небольшие файлы целиком (для JSON-указателей) — LRU в памяти процесса
_small: OrderedDict[str, bytes] = OrderedDict()
_small_lock = threading.Lock()


def read_small(path: str, max_bytes: int = 8_000_000) -> bytes:
    with _small_lock:
        if path in _small:
            _small.move_to_end(path)
            return _small[path]
    data = _req(file_url(path)).read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{path} больше {max_bytes} байт")
    with _small_lock:
        _small[path] = data
        while sum(len(v) for v in _small.values()) > 64_000_000:
            _small.popitem(last=False)
    return data


def list_files(refresh: bool = False) -> list[dict]:
    """Список файлов датасета [{path, size}]; кешируется в data/hf_cyber_files.json."""
    if os.path.exists(FILES_CACHE) and not refresh:
        return json.load(open(FILES_CACHE))
    url = f"https://huggingface.co/api/datasets/{REPO}/tree/{REVISION}?recursive=true&limit=1000"
    out = []
    while url:
        r = _req(url)
        out += [{"path": x["path"], "size": x["size"]} for x in json.load(r) if x["type"] == "file"]
        m = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("Link") or "")
        url = m.group(1) if m else None
    os.makedirs(DATA, exist_ok=True)
    json.dump(out, open(FILES_CACHE, "w"))
    return out


# ---------------------------------------------------------------- классификация файлов

SKIP_NAMES = re.compile(r"(^|/)(\.gitattributes|LICENSE|\.openclaude__settings\.local\.json)$|__dup\d+|\.py$")


def category_of(path: str) -> str:
    if "/" in path:
        return path.split("/")[0]
    if "__" in path:
        return path.split("__")[0]
    return "general"


def base_name(path: str) -> str:
    return path.split("/")[-1].split("__")[-1]


def is_archive(path: str) -> bool:
    return path.endswith((".gz", ".tar", ".zip"))


def is_text_file(path: str) -> bool:
    """Файлы со знаниями (а не архивы исходников и логи сборки ARVO)."""
    if SKIP_NAMES.search(path) or is_archive(path):
        return False
    if "__arvo__" in path:
        return path.endswith("__description.txt")
    return path.endswith((".json", ".jsonl", ".md", ".txt", ".csv"))


def dedupe(files: list[dict]) -> list[dict]:
    """В датасете много копий (в корне и в папке темы, __dupN). Оставляем по одной: одинаковые имя и размер."""
    seen, out = set(), []
    for f in sorted(files, key=lambda f: ("/" not in f["path"], len(f["path"]))):
        key = (base_name(f["path"]), f["size"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
