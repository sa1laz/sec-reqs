#!/usr/bin/env python3
"""Запросы к датасету Vyber07/cyber-security по HTTP без скачивания на диск.

Токен берётся из HF_TOKEN в .env рядом со скриптом. Данные читаются потоком
и на диск не пишутся; кешируется только список файлов (data/hf_cyber_files.json).

  hfq.py ls [REGEX] [--all]        список файлов (по умолчанию без дубликатов)
  hfq.py head PATH [-n BYTES]      первые байты файла
  hfq.py grep REGEX PATH [-m N] [-c CHARS] [-i] [--count]
                                   потоковый поиск по строкам файла
"""
import argparse, json, os, re, sys, urllib.parse, urllib.request

REPO = "Vyber07/cyber-security"
HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "data", "hf_cyber_files.json")


def token():
    for line in open(os.path.join(HERE, ".env")):
        if line.startswith("HF_TOKEN="):
            return line.split("=", 1)[1].strip().strip("'\"")
    sys.exit("HF_TOKEN не найден в .env")


def req(url, rng=None):
    h = {"Authorization": "Bearer " + token()}
    if rng:
        h["Range"] = rng
    return urllib.request.urlopen(urllib.request.Request(url, headers=h))


def file_url(path):
    return f"https://huggingface.co/datasets/{REPO}/resolve/main/" + urllib.parse.quote(path)


def index(refresh=False):
    if os.path.exists(INDEX) and not refresh:
        return json.load(open(INDEX))
    url, out = f"https://huggingface.co/api/datasets/{REPO}/tree/main?recursive=true&limit=1000", []
    while url:
        r = req(url)
        out += [{"path": x["path"], "size": x["size"]} for x in json.load(r) if x["type"] == "file"]
        m = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("Link") or "")
        url = m.group(1) if m else None
    json.dump(out, open(INDEX, "w"))
    return out


def cmd_ls(a):
    files = index(a.refresh)
    if a.regex:
        files = [f for f in files if re.search(a.regex, f["path"], re.I)]
    if not a.all:  # дубликаты: одинаковый размер и то же имя без префиксов/__dup
        seen, uniq = set(), []
        for f in sorted(files, key=lambda f: len(f["path"])):
            base = re.sub(r"__dup\d+", "", f["path"].split("/")[-1]).split("__")[-1]
            if (f["size"], base) not in seen:
                seen.add((f["size"], base))
                uniq.append(f)
        files = uniq
    for f in sorted(files, key=lambda f: -f["size"]):
        print(f"{f['size'] / 1e6:10.2f} MB  {f['path']}")
    print(f"# {len(files)} файлов, {sum(f['size'] for f in files) / 1e9:.2f} ГБ", file=sys.stderr)


def cmd_head(a):
    sys.stdout.write(req(file_url(a.path), f"bytes=0-{a.n - 1}").read().decode("utf-8", "replace"))


def cmd_grep(a):
    rx = re.compile(a.regex.encode(), re.I if a.i else 0)
    hits = n = 0
    for line in req(file_url(a.path)):
        n += 1
        m = rx.search(line)
        if not m:
            continue
        hits += 1
        if not a.count:
            s = max(0, m.start() - a.c // 4)
            print(f"[{n}] " + line[s:s + a.c].decode("utf-8", "replace").rstrip())
            if hits >= a.m:
                break
    print(f"# совпадений: {hits}, просмотрено строк: {n}", file=sys.stderr)


p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
sp = p.add_subparsers(dest="cmd", required=True)
s = sp.add_parser("ls"); s.add_argument("regex", nargs="?"); s.add_argument("--all", action="store_true")
s.add_argument("--refresh", action="store_true"); s.set_defaults(f=cmd_ls)
s = sp.add_parser("head"); s.add_argument("path"); s.add_argument("-n", type=int, default=2000); s.set_defaults(f=cmd_head)
s = sp.add_parser("grep"); s.add_argument("regex"); s.add_argument("path")
s.add_argument("-m", type=int, default=5); s.add_argument("-c", type=int, default=1500)
s.add_argument("-i", action="store_true"); s.add_argument("--count", action="store_true"); s.set_defaults(f=cmd_grep)
a = p.parse_args()
a.f(a)
