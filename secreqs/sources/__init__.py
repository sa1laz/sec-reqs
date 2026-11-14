"""Реестр источников. Порядок задаёт порядок в list_sources и search_all.

Каждая строка — "модуль:Класс". Включить/выключить источники без правки кода:
  SECREQS_SOURCES=cis,hf   (имена источников — атрибут name; по умолчанию — все из реестра, которые готовы к работе)
"""
REGISTRY = [
    "secreqs.sources.cis:CisSource",
    "secreqs.sources.catalog:CatalogSource",
    "secreqs.sources.hf_cyber:HfCyberSource",
]
