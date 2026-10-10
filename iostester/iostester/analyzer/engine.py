"""API Security Test Engine (Phase 4).

Loads YAML rules (one per OWASP API Top 10 category), evaluates passive
checks against every captured transaction, then runs active mutations by
replaying requests from the session store with `httpx`.

Design goals: rule-driven (community can add YAML rules), conservative by
default (active tests are opt-in and rate-limited), and evidence-preserving
(every finding references tx_ids with redacted request/response evidence).
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Callable

import yaml

from ..core.util import (
    dedupe_keep_order,
    get_header,
    is_json_content_type,
    normalize_path_template,
    path_id_candidates,
    safe_json_loads,
    shannon_entropy,
)
from ..interceptor.capture import TrafficStore
from .active import MUTATORS, ActiveContext, replay_request
from .model import Finding, OWASP_API_TOP10, SEVERITY_ORDER

RULES_DIR = Path(__file__).resolve().parent / "rules"

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b")
TOKEN_PARAM_RE = re.compile(
    r"(?:^|[?&])(token|access_token|api_key|apikey|auth|authorization|session|jwt|bearer|password|pwd|secret)=([^&#\s]{6,})",
    re.I,
)
SENSITIVE_FIELD_RE = re.compile(
    r'"(password|passwd|pwd|secret|token|api_key|apikey|access_token|refresh_token|'
    r'ssn|nric|ktp|nik|card_number|credit_card|cvv|pin|salary|internal|is_admin|isadmin|'
    r'role|permissions?)"\s*:\s*("(?:[^"\\]|\\.)*"|true|false|\d+)',
    re.I,
)
STACK_TRACE_RE = re.compile(
    r"(stack trace|traceback|at [\w.$]+\([^)]*\.java:\d+|Exception in thread|"
    r"Fatal error:|Notice: Undefined|Warning: mysql_|SQL syntax.*MySQL|"
    r"ORA-\d{5}|PostgreSQL.*ERROR|Microsoft OLE DB)",
    re.I,
)
FLOW_MARKERS = re.compile(
    r"/(checkout|payment|pay|transfer|purchase|order|topup|top-up|withdraw|redeem|"
    r"voucher|cashout|wallet|transaction|subscribe|upgrade)",
    re.I,
)
ADMIN_MARKERS = re.compile(r"/(admin|internal|debug|manage|staff|superuser|console)", re.I)

PII_PATTERNS = {
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"),
    "phone_id": re.compile(r"(?:\+62|62|08)\d{8,12}"),
    "ktp_16": re.compile(r"\b\d{16}\b"),
    "card_like": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}

DEFAULT_HOST_EXCLUDES = (
    "app-measurement.com",
    "firebase",
    "googleapis.com",
    "doubleclick.net",
    "appsflyer",
    "datadoghq.com",
    "braze",
    "crashlytics",
    "sentry.io",
    "facebook.com",
    "adjust.com",
    "amplitude.com",
    "netcoresmartech.com",
    "scorecardresearch",
    "apple.com",
)


class RuleSet:
    def __init__(self, path: Path):
        self.path = path
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.rules: list[dict[str, Any]] = data.get("rules", [])

    def by_id(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None

    @staticmethod
    def default() -> "RuleSet":
        return RuleSet(RULES_DIR / "owasp_api_top10.yaml")


def load_ruleset(name: str | None) -> RuleSet:
    if not name or name in ("owasp-api-top10", "default", "owasp_api_top10.yaml"):
        return RuleSet.default()
    p = Path(name)
    if not p.exists():
        p = RULES_DIR / name
    if not p.exists():
        raise FileNotFoundError(f"Ruleset not found: {name}")
    return RuleSet(p)


# ---------------------------------------------------------------------------
# passive checks: fn(tx, rule) -> Optional[dict] (evidence) or None
# ---------------------------------------------------------------------------

def _resp_headers_dict(tx: dict) -> dict[str, str]:
    out = {}
    for k, v in tx.get("resp_headers") or []:
        out.setdefault(k.lower(), v)
    return out


def _req_headers_dict(tx: dict) -> dict[str, str]:
    out = {}
    for k, v in tx.get("req_headers") or []:
        out.setdefault(k.lower(), v)
    return out


def check_missing_hsts(tx: dict, rule: dict) -> dict | None:
    if not tx.get("host") or tx.get("scheme") != "https":
        return None
    if tx.get("status") is None:
        return None
    h = _resp_headers_dict(tx)
    if "strict-transport-security" not in h:
        return {
            "host": tx["host"],
            "path": tx.get("path"),
            "observed_headers": sorted(h.keys()),
        }
    return None


def check_weak_cors(tx: dict, rule: dict) -> dict | None:
    h = _resp_headers_dict(tx)
    acao = h.get("access-control-allow-origin")
    if not acao:
        return None
    acac = (h.get("access-control-allow-credentials") or "").lower() == "true"
    req_h = _req_headers_dict(tx)
    origin = req_h.get("origin")
    reflected = bool(origin and acao == origin)
    if acac and (acao == "*" or reflected):
        return {
            "host": tx["host"],
            "path": tx.get("path"),
            "access-control-allow-origin": acao,
            "access-control-allow-credentials": "true",
            "request_origin": origin,
        }
    return None


def check_verbose_errors(tx: dict, rule: dict) -> dict | None:
    body = tx.get("resp_body_decoded") or tx.get("resp_body")
    if not body:
        return None
    text = body[:65536].decode("utf-8", "replace")
    m = STACK_TRACE_RE.search(text)
    if m:
        return {
            "host": tx["host"],
            "path": tx.get("path"),
            "status": tx.get("status"),
            "match": m.group(0)[:160],
        }
    return None


def check_missing_cache_control(tx: dict, rule: dict) -> dict | None:
    if tx.get("status") != 200:
        return None
    h = _resp_headers_dict(tx)
    if "cache-control" in h:
        return None
    body = tx.get("resp_body_decoded") or b""
    if not body:
        return None
    text = body[:65536].decode("utf-8", "replace")
    hits = [m.group(1) for m in SENSITIVE_FIELD_RE.finditer(text)]
    if hits or JWT_RE.search(text):
        return {
            "host": tx["host"],
            "path": tx.get("path"),
            "sensitive_fields": dedupe_keep_order(hits)[:8],
            "jwt_present": bool(JWT_RE.search(text)),
        }
    return None


def check_token_in_url(tx: dict, rule: dict) -> dict | None:
    q = tx.get("query") or ""
    m = TOKEN_PARAM_RE.search("?" + q)
    if not m:
        return None
    return {
        "host": tx["host"],
        "path": tx.get("path"),
        "parameter": m.group(1),
        "value_preview": m.group(2)[:6] + "..." if len(m.group(2)) > 6 else m.group(2),
    }


def check_jwt_no_expiry(tx: dict, rule: dict) -> dict | None:
    for k, v in (tx.get("req_headers") or []):
        if k.lower() == "authorization":
            m = JWT_RE.search(v)
            if not m:
                continue
            payload = _decode_jwt_payload(m.group(0))
            if payload is not None and "exp" not in payload:
                return {
                    "host": tx["host"],
                    "path": tx.get("path"),
                    "claims": sorted(payload.keys()),
                    "jwt_preview": m.group(0)[:24] + "...",
                }
    return None


def _decode_jwt_payload(token: str) -> dict | None:
    import base64

    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:  # noqa: BLE001
        return None


def check_basic_auth_no_tls(tx: dict, rule: dict) -> dict | None:
    if tx.get("scheme") == "https":
        return None
    h = _req_headers_dict(tx)
    auth = h.get("authorization") or ""
    if auth.lower().startswith("basic "):
        return {"host": tx["host"], "path": tx.get("path"), "scheme": tx.get("scheme")}
    return None


def check_sensitive_flow(tx: dict, rule: dict) -> dict | None:
    m = FLOW_MARKERS.search(tx.get("path") or "")
    if not m:
        return None
    return {"host": tx["host"], "path": tx.get("path"), "flow_marker": m.group(1)}


def check_shadow_endpoints(tx: dict, rule: dict) -> dict | None:
    host = tx.get("host") or ""
    flags = []
    if re.search(r"(^|[.-])(staging|qa|dev|uat|test|sandbox|internal)\b", host):
        flags.append("non-production-host")
    if re.search(r"/v?\d+(\.\d+)?/", tx.get("path") or "") and not re.search(r"/v\d+/", tx.get("path") or ""):
        flags.append("unversioned-path")
    if flags:
        return {"host": host, "path": tx.get("path"), "flags": flags}
    return None


def check_unsafe_consumption(tx: dict, rule: dict) -> dict | None:
    host = tx.get("host") or ""
    if not host:
        return None
    first_party = tx.get("_first_party")  # annotated by the engine
    if first_party:
        return None
    ct = (_resp_headers_dict(tx).get("content-type") or "").lower()
    body = tx.get("resp_body_decoded") or b""
    if "text/html" in ct and body[:256].lstrip()[:1] == b"<" and tx.get("method") in ("GET", "POST"):
        # HTML payload into an API consumer: sanitization must be explicit
        req_ct = (_req_headers_dict(tx).get("accept") or "")
        if "json" in req_ct:
            return {
                "host": host,
                "path": tx.get("path"),
                "response_content_type": ct,
                "request_accept": req_ct,
            }
    # weak or token-looking third party URL in request body/query consumed later
    return None


CHECKS: dict[str, Callable[[dict, dict], dict | None]] = {
    "missing_hsts": check_missing_hsts,
    "weak_cors": check_weak_cors,
    "verbose_errors": check_verbose_errors,
    "missing_cache_control": check_missing_cache_control,
    "token_in_url": check_token_in_url,
    "jwt_no_expiry": check_jwt_no_expiry,
    "basic_auth_no_tls": check_basic_auth_no_tls,
    "sensitive_flow": check_sensitive_flow,
    "shadow_endpoints": check_shadow_endpoints,
    "unsafe_consumption": check_unsafe_consumption,
}


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

class Engine:
    def __init__(
        self,
        store: TrafficStore,
        session_name: str,
        exclude_hosts: tuple[str, ...] = DEFAULT_HOST_EXCLUDES,
        log: Callable[[str], None] | None = None,
        progress: Callable[[str, int, int], None] | None = None,
    ):
        self.store = store
        self.session_name = session_name
        self.exclude_hosts = exclude_hosts
        self.log = log or (lambda m: None)
        self.progress = progress
        self._finding_seq = 0

    # -- helpers --------------------------------------------------------
    def _new_id(self, rule: dict) -> str:
        self._finding_seq += 1
        return f"F-{self._finding_seq:04d}"

    def _finding(self, rule: dict, evidence: dict, confidence: str | None = None,
                 description: str | None = None, tx_ids: list[str] | None = None) -> Finding:
        cat = rule["category"]
        return Finding(
            id=self._new_id(rule),
            rule_id=rule["id"],
            title=rule["title"],
            category=cat,
            category_name=OWASP_API_TOP10.get(cat, cat),
            severity=rule.get("severity", "info"),
            confidence=confidence or rule.get("confidence", "medium"),
            description=(description or rule.get("description", "")).strip(),
            evidence=evidence,
            remediation=(rule.get("remediation") or "").strip(),
            references=rule.get("references", []),
            tx_ids=tx_ids or ([evidence.get("tx_id")] if evidence.get("tx_id") else []),
        )

    def is_excluded(self, host: str | None) -> bool:
        if not host:
            return True
        h = host.lower()
        return any(x in h for x in self.exclude_hosts)

    # -- passive phase ----------------------------------------------------
    def run_passive(self, ruleset: RuleSet) -> list[Finding]:
        txs = self.store.iter_transactions()
        self.log(f"passive scan: {len(txs)} transactions")
        findings: list[Finding] = []
        rules = [r for r in ruleset.rules if r.get("type", "passive") == "passive"]
        for i, tx in enumerate(txs):
            if self.is_excluded(tx.get("host")):
                continue
            tx["_first_party"] = self._is_first_party(tx.get("host"))
            for rule in rules:
                m = rule.get("match") or {}
                if m.get("require_https") and tx.get("scheme") != "https":
                    continue
                if m.get("status") and tx.get("status") != m["status"]:
                    continue
                if m.get("status_gte") and (tx.get("status") or 0) < m["status_gte"]:
                    continue
                check = CHECKS.get(rule.get("check"))
                if not check:
                    continue
                try:
                    ev = check(tx, rule)
                except Exception as exc:  # noqa: BLE001
                    self.log(f"rule {rule['id']} check error: {exc}")
                    continue
                if ev:
                    ev["tx_id"] = tx.get("tx_id")
                    findings.append(self._finding(rule, ev))
            if self.progress and i % 25 == 0:
                self.progress("passive", i, len(txs))
        return findings

    def _is_first_party(self, host: str | None) -> bool:
        return not self.excluded_host(host)

    def excluded_host(self, host: str | None) -> bool:
        return self.is_excluded(host)

    # -- active phase ------------------------------------------------------
    def run_active(
        self,
        ruleset: RuleSet,
        selected_ids: list[str] | None = None,
        allow_hosts: list[str] | None = None,
        burst: int = 12,
        delay: float = 0.4,
        max_requests: int = 300,
    ) -> list[Finding]:
        ctx = ActiveContext(
            store=self.store,
            session_name=self.session_name,
            allow_hosts=allow_hosts or [],
            burst=burst,
            delay=delay,
            max_requests=max_requests,
            log=self.log,
        )
        findings: list[Finding] = []
        rules = [
            r for r in ruleset.rules
            if r.get("type") == "active" and (not selected_ids or r["id"] in selected_ids)
        ]
        for rule in rules:
            mutator = MUTATORS.get(rule.get("mutator") or "")
            if not mutator:
                self.log(f"no mutator registered for rule {rule['id']}")
                continue
            self.log(f"active: {rule['id']} ({rule['title']})")
            try:
                results = mutator(ctx, rule)
            except Exception as exc:  # noqa: BLE001
                self.log(f"rule {rule['id']} failed: {exc}")
                continue
            check = CHECKS.get(rule.get("check")) if rule.get("check") else None
            for res in results:
                ev = res.get("evidence") or {}
                if res.get("tx_id"):
                    ev["tx_id"] = res["tx_id"]
                confidence = res.get("confidence", rule.get("confidence", "medium"))
                description = res.get("description") or rule.get("description", "")
                findings.append(
                    self._finding(rule, ev, confidence=confidence, description=description,
                                  tx_ids=res.get("tx_ids") or ([res["tx_id"]] if res.get("tx_id") else []))
                )
        return findings

    # -- orchestration -----------------------------------------------------
    def run_all(
        self,
        ruleset: RuleSet,
        active: bool = False,
        active_rules: list[str] | None = None,
        allow_hosts: list[str] | None = None,
        burst: int = 12,
        delay: float = 0.4,
    ) -> list[Finding]:
        findings = self.run_passive(ruleset)
        if active:
            findings += self.run_active(
                ruleset, selected_ids=active_rules, allow_hosts=allow_hosts, burst=burst, delay=delay
            )
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.rule_id))
        return findings


def load_store(session) -> TrafficStore:  # type: ignore[no-untyped-def]
    return TrafficStore(session.db_path)
