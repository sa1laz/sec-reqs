"""Реестр загрузчиков каталога. Каждый модуль: load() -> int (число элементов);
необязательно SELF_NS = {framework_id: ns} — элементы стандарта сами являются id в этом пространстве имён
(например, элементы nist-800-53 — это id ns «nist-800-53»), чтобы связи находили их."""
LOADERS = [
    "stig", "scuba", "nist_oscal",
    "compliance_as_code", "prowler", "kyverno", "k8s_pss",
    "owasp", "atlas",
    "attack", "d3fend", "cwe", "vulns",
]
