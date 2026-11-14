#!/usr/bin/env python3
"""Смоук-тест MCP-сервера через настоящий stdio-клиент: список инструментов и пара вызовов на каждый источник.

  .venv/bin/python tests/smoke_mcp.py
"""
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CALLS = [
    ("list_sources", {}),
    ("search_all", {"query": "kubernetes network policy", "limit_per_source": 3}),
    ("cis_search_benchmarks", {"query": "eks"}),
    ("cis_get_recommendation", {"benchmark": "EKS Auto Mode", "id": "4.3.1", "fields": ["audit"]}),
    ("hf_overview", {}),
    ("hf_search", {"query": "kerberoasting detection", "limit": 3}),
    ("hf_find_cve", {"cve": "CVE-2021-44228", "limit": 3}),
    ("hf_list_files", {"pattern": "mitre", "limit": 5}),
    ("hf_read_file", {"path": "blue-team/blue-team__hardening-guides.json", "length": 300}),
    ("hf_grep_file", {"path": "vulnerability-intelligence/mitre-attack-techniques.json", "regex": "T1558", "max_hits": 2}),
    ("hf_get_record", {"id": 1, "max_chars": 500}),
    ("req_frameworks", {}),
    ("req_documents", {"framework": "stig", "query": "kubernetes"}),
    ("req_search", {"query": "PermitRootLogin", "limit": 3}),
    ("req_list", {"framework": "scuba", "document": "gws-gmail", "include": ["fix"], "limit": 2}),
    ("req_related", {"ns": "nist-800-53", "id": "AC-2", "per_framework": 1}),
    ("req_related", {"uid": "cis:26485:2.5", "per_framework": 2}),
    ("req_cve", {"cve": "CVE-2021-44228", "nvd": False}),
    ("cis_get_benchmark", {"benchmark": "kubernetes"}),
]


async def main():
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, "run_mcp.py")])
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        init = await s.initialize()
        print("server:", init.server_info.name, init.server_info.version)
        tools = (await s.list_tools()).tools
        print("tools:", ", ".join(t.name for t in tools))
        fails = 0
        for name, args in CALLS:
            res = await s.call_tool(name, args)
            text = "".join(getattr(c, "text", "") for c in res.content)
            print(f"\n== {name} {json.dumps(args, ensure_ascii=False)} → {'ERROR' if res.is_error else 'ok'}")
            print(text[:900])
            fails += res.is_error
        print(f"\nнеожиданных ошибок: {fails}")
        return fails


sys.exit(asyncio.run(main()))
