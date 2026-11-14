#!/usr/bin/env python3
"""Точка входа MCP-сервера sec-reqs (stdio). Работает из любой текущей папки."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secreqs.server import main  # noqa: E402

main()
