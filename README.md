# sec-reqs

Расширяемый MCP-сервер с базами знаний по требованиям и практикам безопасности: агент ищет
по ним, сверяет конфигурации с бенчмарками и находит пробелы.

Источники подключаются модулями. Сейчас их два:

| Источник | Префикс | Что внутри | Где данные |
|---|---|---|---|
| CIS Benchmarks | `cis_` | ~350 бенчмарков, ~42 тыс. рекомендаций: аудит, исправление, профили, CIS Controls | локально, `cis/cis.db` (собирается из PDF) |
| HF `Vyber07/cyber-security` | `hf_` | CVE из NVD, MITRE ATT&CK, разборы атак/защиты, IR-playbook'и, hardening, комплаенс, документация AWS | на Hugging Face; локально только поисковый индекс `data/hf_cyber.db` |

Данные в репозиторий не входят: тексты CIS лицензированы CC BY-NC-SA 4.0 и по условиям CIS не
публикуются, датасет HF закрыт (gated). Здесь только код, который их собирает и обслуживает.

## Инструменты

Общие:

| Инструмент | Что делает |
|---|---|
| `list_sources` | подключённые источники, статистика, чем открывать результаты; неподключённые — с причиной |
| `search_all` | полнотекстовый поиск сразу по всем источникам, результаты сгруппированы по источнику |

CIS (`secreqs/sources/cis.py`):

| Инструмент | Что делает |
|---|---|
| `cis_search_benchmarks` | поиск бенчмарка по технологии (понимает aws, gcp, k8s, rhel, gws…) |
| `cis_get_benchmark` | версия, профили, разделы с числом рекомендаций |
| `cis_search_recommendations` | полнотекстовый поиск (bm25) с фильтрами по бенчмарку, профилю, статусу |
| `cis_get_recommendation` | рекомендация целиком по `uid` или бенчмарк + номер |
| `cis_list_recommendations` | рекомендации по порядку; `include=["audit"]` — для сверки конфигурации |
| `cis_find_by_control` | покрытие CIS Control v8/v7 с фильтром по IG |

Hugging Face (`secreqs/sources/hf_cyber/`):

| Инструмент | Что делает |
|---|---|
| `hf_search` | полнотекстовый поиск по индексу, фрагменты подгружаются с HF |
| `hf_get_record` | запись целиком (текстом или исходным JSON) |
| `hf_find_cve` | все записи, где упоминается CVE |
| `hf_overview` | темы датасета и покрытие индекса |
| `hf_list_files` | файлы датасета (без дублей и архивов по умолчанию) |
| `hf_read_file` | кусок файла по байтам (Range-запрос) |
| `hf_grep_file` | потоковый поиск регулярного выражения по файлу, без скачивания |

## Установка

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
echo 'HF_TOKEN=hf_…' > .env        # токен аккаунта с доступом к датасету
```

### Данные CIS

PDF скачиваются вручную из [CIS WorkBench](https://workbench.cisecurity.org/) (нужен бесплатный
аккаунт) в `cis/pdf/<workbench_id>.pdf`; какие файлы брать — в `cis/download_manifest.json`. Затем:

```bash
.venv/bin/python cis/build_all.py && .venv/bin/python cis/qa.py && .venv/bin/python cis/build_db.py
```

Подробности о формате и качестве разбора — [cis/README.md](cis/README.md).

### Индекс датасета HF

```bash
.venv/bin/python -m secreqs.sources.hf_cyber.build_index --max-mb 3000
```

В индекс попадают текстовые файлы (JSON, JSONL, CSV, Markdown, описания ARVO), без копий и без
архивов исходников ARVO — это ~3,7 ГБ из 95 ГБ. Сами тексты в индекс не копируются: хранится FTS5
без содержимого и адрес записи (байтовое смещение или JSON-указатель), записи читаются с HF при
запросе. Запуск можно прерывать и повторять: готовые файлы пропускаются. `--list` показывает план,
`--max-mb 50` — только небольшие файлы (полминуты).

## Подключение к Claude Code

```bash
claude mcp add sec-reqs --scope local -- "$PWD/.venv/bin/python" "$PWD/run_mcp.py"
```

Источники без данных не подключаются, сервер всё равно стартует (`list_sources` покажет причину).
Переменные окружения: `SECREQS_SOURCES=cis,hf` — оставить только перечисленные, `CIS_DB`,
`HF_CYBER_DB`, `HF_TOKEN`, `HF_DATASET`.

Проверка: `.venv/bin/python tests/smoke_mcp.py` — поднимает сервер через stdio и вызывает инструменты.

## Как добавить источник

1. Модуль `secreqs/sources/<name>.py` (или пакет) с классом-наследником `secreqs.core.Source`:
   `name` (префикс инструментов), `title`, `instructions` (кусок подсказки для агента),
   `available()`, `register(mcp)`, по желанию `stats()` и `search()` — тогда источник участвует в `search_all`.
2. Строка `"secreqs.sources.<name>:<Класс>"` в `secreqs/sources/__init__.py`.
3. Тяжёлые данные — в `data/` (исключена из git) со скриптом сборки рядом с модулем.

Ошибки, которые должен увидеть агент, — `ToolError`; прочие исключения SDK скрывает от клиента.

## Прочее

- `docs/` — таблицы мер «мера — риск — реализация» для EKS Auto Mode и Google Workspace.
- `hfq.py` — CLI для датасета HF: `ls`, `head`, `grep` без скачивания.
