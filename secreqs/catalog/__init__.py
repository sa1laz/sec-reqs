"""Единый каталог требований из открытых источников (STIG, SCuBA, NIST, OWASP, MITRE…).

Каждый загрузчик (secreqs/catalog/loaders/<name>.py) скачивает первоисточник в data/raw/<name>/
и пишет нормализованный JSONL в data/catalog/<name>.jsonl. Затем build собирает все JSONL
в data/catalog.db (SQLite + FTS5 + таблица связей между стандартами).

Записи JSONL (поле type):
  framework — стандарт/источник: id, title, version, published, kind, publisher, license, url, description
  document  — документ внутри (отдельный STIG, продукт SCuBA, матрица ATT&CK): framework, id, title, version, date, url
  item      — требование/мера/техника: framework, document, id, title, kind, parent, severity, profiles[],
              text{description, rationale, check, fix, default, …}, refs[], maps[{ns, id, rel}], extra{}
Пространства имён связей (maps.ns) — см. NS в model.py.
"""
