"""MCP-сервер sec-reqs: собирает инструменты всех готовых источников из реестра.

  .venv/bin/python run_mcp.py          # stdio
  .venv/bin/python -m secreqs          # то же, из корня репозитория
"""
from __future__ import annotations

import importlib
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from secreqs import __version__
from secreqs.core import RO, Source
from secreqs.sources import REGISTRY

HEADER = """\
sec-reqs — базы знаний по требованиям и практикам безопасности. Источники подключаются модулями;
у инструментов каждого источника свой префикс (cis_, hf_). Начни с list_sources, если не знаешь,
что доступно; search_all — быстрый поиск сразу по всем источникам, дальше уточняй инструментами источника.
Все тексты на английском, поиск полнотекстовый по словам (не по смыслу): формулируй запросы по-английски
и пробуй синонимы и конкретные термины (имя параметра, сервиса, файла), если первый запрос дал мало.
"""


def load_sources() -> tuple[list[Source], dict[str, str]]:
    wanted = {s.strip() for s in os.environ.get("SECREQS_SOURCES", "").split(",") if s.strip()}
    ready, skipped = [], {}
    for spec in REGISTRY:
        mod, cls = spec.split(":")
        try:
            src: Source = getattr(importlib.import_module(mod), cls)()
        except Exception as e:  # сломанный источник не должен ронять весь сервер
            skipped[spec] = f"ошибка загрузки: {e!r}"
            traceback.print_exc(file=sys.stderr)
            continue
        if wanted and src.name not in wanted:
            skipped[src.name] = "выключен через SECREQS_SOURCES"
            continue
        ok, why = src.available()
        if ok:
            ready.append(src)
        else:
            skipped[src.name] = why
    return ready, skipped


def build() -> MCPServer:
    sources, skipped = load_sources()
    instructions = HEADER + "".join(f"\n## {s.title} (префикс {s.name}_)\n{s.instructions.strip()}\n" for s in sources)
    mcp = MCPServer("sec-reqs", title="Security requirements knowledge base", instructions=instructions,
                    version=__version__)
    by_name = {s.name: s for s in sources}

    @mcp.tool(annotations=RO)
    def list_sources() -> dict:
        """Подключённые источники знаний: название, статистика, инструменты для перехода к записи.
        Также показывает источники, которые не загружены, и почему (например, не собрана база)."""
        rows = []
        for s in sources:
            try:
                rows.append({"name": s.name, "title": s.title, "open_with": s.get_tool, **s.stats()})
            except Exception as e:
                rows.append({"name": s.name, "title": s.title, "warnings": [f"статистика недоступна: {type(e).__name__}"]})
        warnings = [f'{r["name"]}: {w}' for r in rows for w in r.get("warnings", [])]
        warnings += [f"{n}: не загружен — {why}" for n, why in skipped.items()]
        return {"status": "degraded" if warnings else "ok", "warnings": warnings, "sources": rows, "not_loaded": skipped}

    @mcp.tool(annotations=RO)
    def search_all(query: str, sources: list[str] | None = None, limit_per_source: int = 5) -> dict:
        """Полнотекстовый поиск сразу по всем источникам (или по перечисленным в sources).

        query: слова или "фраза в кавычках". Результаты сгруппированы по источнику; у каждого id,
        который открывается инструментом из open_with этого источника.
        """
        chosen = [by_name[n] for n in (sources or by_name) if n in by_name]
        if not chosen:
            raise ToolError(f"Нет таких источников. Доступны: {', '.join(by_name)}")
        lim = max(1, min(limit_per_source, 20))

        def run(s: Source):
            try:
                return s.name, {"open_with": s.get_tool, "results": s.search(query, lim)}
            except ToolError as e:
                return s.name, {"error": str(e)}
            except Exception as e:
                traceback.print_exc(file=sys.stderr)
                return s.name, {"error": f"сбой поиска: {type(e).__name__}"}

        with ThreadPoolExecutor(len(chosen)) as ex:
            return {"query": query, "by_source": dict(ex.map(run, chosen))}

    for s in sources:
        s.register(mcp)
    return mcp


def http_app(mcp: MCPServer):
    """Streamable HTTP (без сессий: инструменты не хранят состояние, рестарт пода не рвёт клиентов).
    /healthz — без авторизации. Если задан SECREQS_TOKEN, /mcp требует Authorization: Bearer <token>."""
    import hmac

    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.responses import JSONResponse, PlainTextResponse

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request):
        return PlainTextResponse("ok")

    @mcp.custom_route("/status", methods=["GET"])
    async def status(request):
        """Состояние источников и сборок данных для мониторинга: 200 — всё в порядке, 503 — есть предупреждения."""
        tool = await mcp.call_tool("list_sources", {})
        import json as _j
        content = tool.content if hasattr(tool, "content") else (tool[0] if isinstance(tool, tuple) else tool)
        text = "".join(getattr(c, "text", "") for c in content)
        body = _j.loads(text) if text else {"status": "unknown"}
        # 503 при деградации — чтобы blackbox-проба (valid_status_codes: [200]) поднимала алерт
        return JSONResponse(body, status_code=200 if body.get("status") == "ok" else 503)

    app = mcp.streamable_http_app(
        stateless_http=True, json_response=True, host="0.0.0.0",
        # за gateway Host — имя сервиса; от DNS rebinding защищают NetworkPolicy и токен
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
    token = os.environ.get("SECREQS_TOKEN", "")
    if not token:
        return app

    async def guarded(scope, receive, send):
        if scope["type"] == "http" and scope["path"] != "/healthz":
            auth = dict(scope["headers"]).get(b"authorization", b"").decode()
            if not hmac.compare_digest(auth, f"Bearer {token}"):
                return await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
        return await app(scope, receive, send)

    return guarded


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="sec-reqs MCP server")
    ap.add_argument("--http", action="store_true", default=os.environ.get("SECREQS_TRANSPORT") == "http",
                    help="streamable HTTP вместо stdio (или SECREQS_TRANSPORT=http)")
    ap.add_argument("--host", default=os.environ.get("SECREQS_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("SECREQS_PORT", "8000")))
    a = ap.parse_args()
    mcp = build()
    if not a.http:
        mcp.run("stdio")
        return
    import uvicorn

    uvicorn.run(http_app(mcp), host=a.host, port=a.port, log_level="info", access_log=False)


if __name__ == "__main__":
    main()
