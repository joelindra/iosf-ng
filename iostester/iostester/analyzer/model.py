"""Findings model for the API security test engine (Phase 4)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..core.util import now_iso, redact_headers

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_COLORS = {
    "critical": "#8b1a1a",
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#f9a825",
    "info": "#1565c0",
}


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    category: str                 # OWASP API Top 10 id, e.g. API1:2023
    category_name: str
    severity: str                 # critical|high|medium|low|info
    confidence: str               # high|medium|low
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tx_ids: list[str] = field(default_factory=list)
    created: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def save_findings(findings: list[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": now_iso(),
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Finding(**f) for f in data.get("findings", [])]


def severity_summary(findings: list[Finding]) -> dict[str, int]:
    out = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def redact_evidence(tx: dict[str, Any]) -> dict[str, Any]:
    """Strip secrets from an evidence payload for reports."""
    out = {
        "tx_id": tx.get("tx_id"),
        "method": tx.get("method"),
        "host": tx.get("host"),
        "path": tx.get("path"),
        "query": tx.get("query"),
        "status": tx.get("status"),
    }
    if tx.get("req_headers"):
        out["req_headers"] = redact_headers(tx["req_headers"])
    if tx.get("resp_headers"):
        out["resp_headers"] = redact_headers(tx["resp_headers"])
    return out


OWASP_API_TOP10 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}
