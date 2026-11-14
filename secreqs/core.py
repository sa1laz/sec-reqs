"""Общие части: базовый класс источника и утилиты поиска.

Источник (Source) — независимый модуль знаний: регистрирует свои инструменты в MCP-сервере
и, по желанию, умеет отвечать на общий поиск (search_all). Новый источник:
  1. класс-наследник Source в secreqs/sources/<name>.py (или пакет);
  2. строка в secreqs/sources/__init__.py:REGISTRY.
"""
from __future__ import annotations

import os
import re
import sqlite3

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("SECREQS_DATA", os.path.join(ROOT, "data"))

# Инструменты только читают локальные данные
RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
# Инструменты, которые ходят во внешний сервис (HF Hub)
RO_REMOTE = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)


class Source:
    """Базовый класс источника знаний."""

    name: str = ""          # короткий идентификатор, он же префикс инструментов
    title: str = ""         # человекочитаемое название
    instructions: str = ""  # фрагмент общих инструкций сервера для агента

    def available(self) -> tuple[bool, str]:
        """(готов ли источник, причина если нет) — например, собрана ли база."""
        return True, ""

    def register(self, mcp) -> None:
        """Зарегистрировать инструменты источника в MCPServer."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Краткая статистика для list_sources."""
        return {}

    def search(self, query: str, limit: int = 5) -> list[dict]:
        """Единый поиск для search_all. Каждый результат: {id, title, snippet, ...}.
        id должен открываться инструментом источника (описан в get_tool)."""
        return []

    get_tool: str = ""      # инструмент, которым открывается результат search()


def read_status(name: str) -> dict | None:
    """Статус последней сборки данных источника (data/<name>_status.json), если сборщик его пишет."""
    import json
    p = os.path.join(DATA, f"{name}_status.json")
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_status(name: str, status: dict) -> None:
    import json
    import time
    os.makedirs(DATA, exist_ok=True)
    status = {"finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **status}
    tmp = os.path.join(DATA, f"{name}_status.json.part")
    json.dump(status, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(tmp, os.path.join(DATA, f"{name}_status.json"))


def ro_db(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


CYRILLIC = re.compile(r"[а-яё]", re.I)


def fts_query(q: str) -> str:
    """Свободный текст → запрос FTS5: слова через AND, «фразы в кавычках» сохраняются,
    слова от 4 букв ищутся как префикс, составные токены (sshd_config, CVE-2024-1) — как фраза."""
    if CYRILLIC.search(q):
        latin = re.sub(r"\s+", " ", re.sub(r"[а-яё]+", " ", q, flags=re.I)).strip()
        raise ToolError("Тексты во всех базах на английском, поиск идёт по словам: переформулируй запрос по-английски "
                        "(например, «шифрование etcd» → «etcd encryption», «MFA для root» → «root MFA»)"
                        + (f". Латинская часть запроса: «{latin}»" if re.search(r"[a-z]", latin, re.I) else "") + ".")
    phrases = re.findall(r'"([^"]+)"', q)
    rest = re.sub(r'"[^"]+"', " ", q)
    toks = re.findall(r"[\w.\-/]+", rest, re.U)
    parts = ['"' + " ".join(re.findall(r"\w+", p, re.U)) + '"' for p in phrases if re.search(r"\w", p)]
    for t in toks:
        t = t.strip(".-/")
        if not t or t.upper() in ("AND", "OR", "NOT"):
            continue
        sub = re.findall(r"\w+", t, re.U)
        if len(sub) > 1:
            parts.append('"' + " ".join(sub) + '"')
        elif sub:
            parts.append(f'"{sub[0]}"*' if len(sub[0]) >= 4 else f'"{sub[0]}"')
    return " AND ".join(parts)


def fts_query_or(q: str) -> str:
    """Тот же запрос, но через OR — запасной вариант, когда AND ничего не нашёл."""
    return fts_query(q).replace(" AND ", " OR ")


def snippet_of(text: str, query: str, width: int = 240) -> str:
    """Фрагмент текста вокруг первого совпадения слова из запроса."""
    text = text or ""
    low = text.lower()
    words = [w.lower() for w in re.findall(r"\w{3,}", query)]
    pos = min((p for p in (low.find(w) for w in words) if p >= 0), default=-1)
    s = max(0, pos - width // 3) if pos >= 0 else 0
    out = re.sub(r"\s+", " ", text[s:s + width]).strip()
    return ("…" if s else "") + out + ("…" if s + width < len(text) else "")
