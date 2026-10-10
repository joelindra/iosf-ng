"""Active test mutators for the API engine (Phase 4, replay layer).

Every mutator receives an ActiveContext and a rule dict and returns a list of
result dicts:

    {"evidence": {...}, "tx_id": str|None, "confidence": "high|medium|low",
     "description": optional override, "tx_ids": [...]}

Safety rails
------------
* Only hosts captured in this session may be replayed (allowlist derived from
  the captured traffic, or narrowed explicitly with --allow-host).
* Requests are rate-limited (delay) and capped (max_requests per run).
* Bodies are truncated when stored; bodies larger than REPLAY_BODY_LIMIT are
  skipped to avoid huge replays.

These are deliberately conservative defaults so the tool can be demonstrated
safely (see the ethics note in the README).
"""
from __future__ import annotations

import base64
import copy
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

import httpx

from ..core.util import (
    get_header,
    is_json_content_type,
    path_id_candidates,
    safe_json_loads,
)
from ..interceptor.capture import RequestRecord, TrafficStore

REPLAY_BODY_LIMIT = 512 * 1024
DEFAULT_TIMEOUT = 15.0
ADMIN_ROLE_WORDS = {"role": "admin", "isAdmin": True, "is_admin": True, "admin": True}
PRIVILEGED_FIELDS = {
    "role": "admin",
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "balance": 999999,
    "credit": 999999,
    "verified": True,
    "isVerified": True,
    "email_verified": True,
    "permissions": ["admin"],
    "scope": "admin",
    "user_type": "admin",
    "userType": "admin",
    "status": "active",
    "approved": True,
}
SUSPICIOUS_RESPONSE_FIELDS = (
    "password",
    "passwd",
    "hash",
    "secret",
    "token",
    "api_key",
    "apikey",
    "ssn",
    "salary",
    "internal",
    "is_admin",
    "isadmin",
    "role",
    "permissions",
    "card",
    "cvv",
    "pin",
    "ktp",
    "nik",
)


@dataclass
class ActiveContext:
    store: TrafficStore
    session_name: str
    allow_hosts: list[str] = field(default_factory=list)
    burst: int = 12
    delay: float = 0.4
    max_requests: int = 300
    log: Callable[[str], None] = lambda m: None

    def __post_init__(self) -> None:
        self._spent = 0
        allowed = set(h.strip().lower() for h in self.allow_hosts if h.strip())
        if not allowed:
            allowed = {t["host"].lower() for t in self.store.iter_transactions() if t.get("host")}
        self._allowed = allowed
        self._client = httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            follow_redirects=False,
            headers={"User-Agent": "iOSTester/replay"},
        )

    # ------------------------------------------------------------------
    def can_target(self, host: str | None) -> bool:
        if not host:
            return False
        return host.lower() in self._allowed

    def budget_ok(self) -> bool:
        return self._spent < self.max_requests

    def send(self, rec: RequestRecord, *, method: str | None = None, url: str | None = None,
             headers: list[tuple[str, str]] | dict[str, str] | None = None,
             content: bytes | None = None, note: str = "") -> httpx.Response | None:
        if not self.budget_ok():
            return None
        if not self.can_target(urlparse(url or rec.url_no_port).hostname):
            self.log(f"skip replay: host not allowed ({rec.host})")
            return None
        self._spent += 1
        hdrs = headers if headers is not None else rec.headers
        if isinstance(hdrs, list):
            hdrs = {k: v for k, v in hdrs}
        # drop hop-by-hop headers that break replay
        for h in ("content-length", "host", "connection", "accept-encoding", "transfer-encoding"):
            hdrs.pop(h, None)
        body = content if content is not None else rec.body
        if body is not None and len(body) > REPLAY_BODY_LIMIT:
            self.log(f"skip replay: body too large ({len(body)} bytes)")
            return None
        try:
            resp = self._client.request(
                method or rec.method,
                url or rec.url_no_port,
                headers=hdrs,
                content=body,
            )
        except Exception as exc:  # noqa: BLE001
            self.log(f"replay error ({note or rec.tx_id}): {exc}")
            return None
        time.sleep(self.delay)
        return resp

    def requests_spent(self) -> int:
        return self._spent


# ---------------------------------------------------------------------------
# mutators
# ---------------------------------------------------------------------------

def mutate_iterate_object_id(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API1: replay object identifiers (n-1/n+1) and compare responses."""
    out: list[dict[str, Any]] = []
    succ = rule.get("match", {}).get("success_status", [200])
    seen_paths: set[str] = set()
    txs = ctx.store.iter_transactions()
    for tx in txs:
        if not ctx.budget_ok():
            break
        if tx.get("method") not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            continue
        if ctx.store and not ctx.can_target(tx.get("host")):
            continue
        path = tx.get("path") or ""
        ids = path_id_candidates(path, tx.get("query") or "")
        if not ids:
            continue
        key = f"{tx['host']}{path}"
        if key in seen_paths:
            continue
        seen_paths.add(key)
        for loc, value in ids[:2]:
            try:
                n = int(value)
            except ValueError:
                continue
            for delta in (+1, -1):
                candidate = str(n + delta)
                if loc == "path":
                    new_path = re.sub(rf"/{re.escape(value)}(?=/|$)", f"/{candidate}", path, count=1)
                    new_url = _swap_url(tx, new_path, tx.get("query") or "")
                else:
                    new_query = re.sub(
                        rf"(?<=[?&])([A-Za-z0-9_\-\[\].]+)={re.escape(value)}(?=&|$)",
                        lambda m: f"{m.group(1)}={candidate}",
                        tx.get("query") or "",
                    )
                    new_url = _swap_url(tx, path, new_query)
                rec = ctx.store.replay_record(tx["tx_id"])
                if not rec:
                    continue
                resp = ctx.send(rec, url=new_url, note=f"bola {value}->{candidate}")
                if resp is None:
                    continue
                body_txt = resp.text[:2000] if resp.content else ""
                same_shape = _similar_json(body_txt)
                if resp.status_code in (401, 403, 404):
                    continue
                if same_shape and resp.status_code in succ and len(body_txt) > 2:
                    out.append(
                        {
                            "tx_id": tx["tx_id"],
                            "confidence": "medium",
                            "evidence": {
                                "endpoint": tx.get("path"),
                                "host": tx.get("host"),
                                "original_id": value,
                                "replayed_id": candidate,
                                "location": loc,
                                "replayed_url": new_url,
                                "status": resp.status_code,
                                "response_excerpt": body_txt[:300],
                            },
                        }
                    )
                    break
            if len(out) >= 8:
                break
    return out


def mutate_mass_assign(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API3: add privileged fields to JSON bodies and observe acceptance."""
    out: list[dict[str, Any]] = []
    for tx in ctx.store.iter_transactions():
        if not ctx.budget_ok():
            break
        if tx.get("method") not in ("POST", "PUT", "PATCH"):
            continue
        if not ctx.can_target(tx.get("host")):
            continue
        body = tx.get("req_body")
        if not body or not is_json_content_type(get_header(tx.get("req_headers") or [], "content-type")):
            continue
        obj = safe_json_loads(body)
        if not isinstance(obj, dict):
            continue
        rec = ctx.store.replay_record(tx["tx_id"])
        if not rec:
            continue
        probe = copy.deepcopy(obj)
        added = {}
        for k, v in PRIVILEGED_FIELDS.items():
            if k not in probe:
                probe[k] = v
                added[k] = v
        if not added:
            continue
        payload = json.dumps(probe).encode()
        resp = ctx.send(
            rec,
            content=payload,
            headers=_headers_with(rec.headers, "content-type", "application/json"),
            note="mass-assign",
        )
        if resp is None:
            continue
        echoed = _echoed_fields(resp.text if resp.content else "", list(added.keys()))
        took_effect = bool(echoed) and resp.status_code < 400
        if took_effect:
            out.append(
                {
                    "tx_id": tx["tx_id"],
                    "confidence": "medium",
                    "evidence": {
                        "endpoint": tx.get("path"),
                        "host": tx.get("host"),
                        "injected_fields": list(added.keys()),
                        "echoed_fields": echoed,
                        "status": resp.status_code,
                        "response_excerpt": (resp.text or "")[:300],
                    },
                }
            )
        elif resp.status_code < 400 and len(resp.content or b"") > 0 and not echoed:
            # accepted silently: still worth a low-confidence note
            pass
        if len(out) >= 6:
            break
    return out


def mutate_probe_field_permissions(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API3: flag responses exposing fields never rendered by the app."""
    out: list[dict[str, Any]] = []
    for tx in ctx.store.iter_transactions():
        if tx.get("method") not in ("GET", "POST"):
            continue
        if not ctx.can_target(tx.get("host")):
            continue
        body = tx.get("resp_body_decoded") or b""
        if not body:
            continue
        text = body[:131072].decode("utf-8", "replace")
        hits = [f for f in SUSPICIOUS_RESPONSE_FIELDS if re.search(rf'"{f}"\s*:', text, re.I)]
        jwt = bool(re.search(r"eyJ[A-Za-z0-9_\-]{8,}\.", text))
        if hits:
            out.append(
                {
                    "tx_id": tx["tx_id"],
                    "confidence": "low",
                    "evidence": {
                        "endpoint": tx.get("path"),
                        "host": tx.get("host"),
                        "fields": hits[:10],
                        "jwt_in_body": jwt,
                    },
                }
            )
        if len(out) >= 8:
            break
    return out


def mutate_burst(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API4: burst N identical requests to check for rate limiting."""
    burst = int(rule.get("match", {}).get("max_burst", ctx.burst))
    burst = max(4, min(burst, ctx.burst))
    txs = [
        t
        for t in ctx.store.iter_transactions(method=None)
        if t.get("method") in ("GET", "POST") and ctx.can_target(t.get("host"))
    ]
    # prefer endpoints that look like auth/search/list operations
    txs.sort(
        key=lambda t: (
            0 if re.search(r"(login|auth|otp|verify|search|list|query|check)", (t.get("path") or ""), re.I) else 1,
            t.get("host") or "",
        )
    )
    out: list[dict[str, Any]] = []
    for tx in txs[:4]:
        if not ctx.budget_ok():
            break
        rec = ctx.store.replay_record(tx["tx_id"])
        if not rec:
            continue
        statuses: list[int] = []
        got_limit = False
        for i in range(burst):
            resp = ctx.send(rec, note=f"burst#{i}")
            if resp is None:
                break
            statuses.append(resp.status_code)
            if resp.status_code in (429, 503) or resp.headers.get("retry-after"):
                got_limit = True
                break
        accept = sum(1 for s in statuses if 200 <= s < 300)
        if not got_limit and len(statuses) >= burst and accept >= burst - 1:
            out.append(
                {
                    "tx_id": tx["tx_id"],
                    "confidence": "medium",
                    "evidence": {
                        "endpoint": tx.get("path"),
                        "host": tx.get("host"),
                        "method": tx.get("method"),
                        "requests_sent": len(statuses),
                        "statuses": statuses,
                        "rate_limit_signals": None,
                    },
                }
            )
        if len(out) >= 3:
            break
    return out


def mutate_admin_path_swap(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API5: try common admin path substitutions on captured endpoints."""
    markers = rule.get("match", {}).get("admin_path_markers", ["admin"])
    out: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    # (a) captured paths already hitting admin-ish surfaces
    for tx in ctx.store.iter_transactions():
        p = tx.get("path") or ""
        for m in markers:
            if re.search(rf"/{m}\b", p, re.I):
                candidates.append(tx)
                break
    # (b) derive admin variants from v1 endpoints
    derived: list[dict[str, Any]] = []
    for tx in ctx.store.iter_transactions():
        p = tx.get("path") or ""
        if not ctx.can_target(tx.get("host")):
            continue
        m = re.match(r"/(v\d+)/(\w+)/(.+)", p)
        if m:
            variant = f"/{m.group(1)}/admin/{m.group(3)}"
            derived.append({"tx": tx, "variant": variant})
    for tx in candidates[:5]:
        if not ctx.budget_ok():
            break
        rec = ctx.store.replay_record(tx["tx_id"])
        if not rec:
            continue
        resp = ctx.send(rec, note="admin-path")
        if resp is None:
            continue
        if resp.status_code < 400:
            out.append(
                {
                    "tx_id": tx["tx_id"],
                    "confidence": "medium",
                    "evidence": {
                        "endpoint": tx.get("path"),
                        "host": tx.get("host"),
                        "status": resp.status_code,
                        "note": "admin-like path reachable with current session",
                    },
                }
            )
        if len(out) >= 5:
            break
    for item in derived[:5]:
        if not ctx.budget_ok() or len(out) >= 8:
            break
        tx = item["tx"]
        rec = ctx.store.replay_record(tx["tx_id"])
        if not rec:
            continue
        new_url = _swap_url(tx, item["variant"], tx.get("query") or "")
        resp = ctx.send(rec, url=new_url, note="admin-derived")
        if resp is None:
            continue
        if resp.status_code < 400 and (resp.content or b""):
            out.append(
                {
                    "tx_id": tx["tx_id"],
                    "confidence": "low",
                    "evidence": {
                        "endpoint": item["variant"],
                        "host": tx.get("host"),
                        "status": resp.status_code,
                        "note": "derived admin endpoint accepted request",
                        "response_excerpt": (resp.text or "")[:200],
                    },
                }
            )
    return out


def mutate_ssrf_url_param(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API7: inject internal targets into URL-ish parameters."""
    hints = set(w.lower() for w in rule.get("match", {}).get("param_hints", ["url", "uri", "redirect"]))
    canaries = [
        "http://127.0.0.1:80/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/",
    ]
    out: list[dict[str, Any]] = []
    for tx in ctx.store.iter_transactions():
        if not ctx.budget_ok():
            break
        if not ctx.can_target(tx.get("host")):
            continue
        query = tx.get("query") or ""
        params = dict(parse_qsl(query, keep_blank_values=True))
        hit_param = None
        for k, v in params.items():
            if k.lower() in hints or re.search(r"(url|uri|link|callback|redirect|next|image|file|path|feed|host)", k, re.I):
                if v.startswith("http") or v.startswith("/") or "." in v:
                    hit_param = k
                    break
        body_param = None
        body_obj = None
        if not hit_param:
            body_obj = safe_json_loads(tx.get("req_body"))
            if isinstance(body_obj, dict):
                for k, v in body_obj.items():
                    if isinstance(v, str) and (k.lower() in hints or re.search(r"(url|uri|link|callback|redirect|next|image|file|path|feed|webhook)", k, re.I)):
                        if v.startswith("http") or v.startswith("/"):
                            body_param = k
                            break
        if not hit_param and not body_param:
            continue
        rec = ctx.store.replay_record(tx["tx_id"])
        if not rec:
            continue
        for canary in canaries[:2]:
            if not ctx.budget_ok():
                break
            if hit_param:
                new_params = dict(params)
                new_params[hit_param] = canary
                new_url = _swap_url(tx, tx.get("path") or "/", urlencode(new_params))
                resp = ctx.send(rec, url=new_url, note="ssrf-query")
            elif body_param and body_obj is not None:
                probe = dict(body_obj)
                probe[body_param] = canary
                resp = ctx.send(
                    rec,
                    content=json.dumps(probe).encode(),
                    headers=_headers_with(rec.headers, "content-type", "application/json"),
                    note="ssrf-body",
                )
            else:
                continue
            if resp is None:
                continue
            text = (resp.text or "")[:1500]
            signal = _ssrf_signal(text, resp.status_code)
            if signal:
                out.append(
                    {
                        "tx_id": tx["tx_id"],
                        "confidence": "low" if signal == "status-change" else "medium",
                        "evidence": {
                            "endpoint": tx.get("path"),
                            "host": tx.get("host"),
                            "parameter": hit_param or body_param,
                            "canary": canary,
                            "status": resp.status_code,
                            "signal": signal,
                            "response_excerpt": text[:250],
                        },
                    }
                )
                break
        if len(out) >= 5:
            break
    return out


def mutate_logout_replay(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API2: replay pre-logout authenticated requests with the old token.

    Detects logout endpoints in the traffic, takes the last authorization
    header seen *before* the logout, and replays an authenticated request
    captured before logout. A 2xx response suggests the token survived.
    """
    txs = ctx.store.iter_transactions()
    logout_idx = None
    logout_tx = None
    for i, t in enumerate(txs):
        if re.search(r"/(logout|signout|sign-out|revoke)", (t.get("path") or ""), re.I):
            logout_idx = i
            logout_tx = t
    if logout_idx is None:
        return []
    pre = [t for t in txs[:logout_idx] if get_header(t.get("req_headers") or [], "authorization")]
    if not pre:
        return []
    # prefer GETs so replay is idempotent
    pre.sort(key=lambda t: (0 if t.get("method") == "GET" else 1))
    auth = get_header(pre[-1].get("req_headers") or [], "authorization")
    if not auth:
        return []
    out: list[dict[str, Any]] = []
    for tx in pre[::-1]:
        if not ctx.budget_ok():
            break
        if tx.get("method") != "GET":
            continue
        rec = ctx.store.replay_record(tx["tx_id"])
        if not rec:
            continue
        resp = ctx.send(rec, note="logout-replay")
        if resp is None:
            continue
        if 200 <= resp.status_code < 300 and (resp.content or b""):
            out.append(
                {
                    "tx_id": tx["tx_id"],
                    "tx_ids": [tx["tx_id"], logout_tx["tx_id"] if logout_tx else ""],
                    "confidence": "medium",
                    "evidence": {
                        "endpoint": tx.get("path"),
                        "host": tx.get("host"),
                        "logout_endpoint": logout_tx.get("path") if logout_tx else None,
                        "status_after_logout": resp.status_code,
                        "response_excerpt": (resp.text or "")[:200],
                    },
                }
            )
            break
    return out


def mutate_replay_with_expired_claims(ctx: ActiveContext, rule: dict) -> list[dict[str, Any]]:
    """API2: replay with a JWT whose exp claim is in the past (signature kept).

    Note: this only verifies server-side expiry enforcement when the server
    accepts the token; signature is preserved so acceptance is meaningful.
    """
    out: list[dict[str, Any]] = []
    for tx in ctx.store.iter_transactions():
        if not ctx.budget_ok():
            break
        if tx.get("method") != "GET":
            continue
        auth = get_header(tx.get("req_headers") or [], "authorization")
        if not auth or not auth.lower().startswith("bearer "):
            continue
        token = auth.split(" ", 1)[1].strip()
        parts = token.split(".")
        if len(parts) != 3:
            continue
        expired = _jwt_set_claim(token, "exp", 1000000000)  # 2001-09-09
        if not expired:
            continue
        rec = ctx.store.replay_record(tx["tx_id"])
        if not rec:
            continue
        headers = _headers_with(rec.headers, "authorization", "Bearer " + expired)
        resp = ctx.send(rec, headers=headers, note="expired-claims")
        if resp is None:
            continue
        if 200 <= resp.status_code < 300 and (resp.content or b""):
            out.append(
                {
                    "tx_id": tx["tx_id"],
                    "confidence": "low",
                    "evidence": {
                        "endpoint": tx.get("path"),
                        "host": tx.get("host"),
                        "status_with_expired_exp": resp.status_code,
                        "note": (
                            "Server accepted a JWT with exp set in the past - verify this "
                            "was not a cached/public response."
                        ),
                    },
                }
            )
            break
    return out


def _ssrf_signal(text: str, status: int) -> str | None:
    if status >= 500:
        return None
    low = text.lower()
    for marker in ("root:", "localhost", "169.254", "metadata", "ec2", "internal server", "connection refused"):
        if marker in low:
            return f"response-mentions-{marker}"
    if re.search(r"(AMI-ID|iam/security-credentials)", text):
        return "metadata-service-response"
    if status in (200, 201) and re.search(r'"<html|<!doctype html', low):
        return "html-returned-for-url-param"
    return None


def _echoed_fields(resp_text: str, fields: list[str]) -> list[str]:
    out = []
    for f in fields:
        if re.search(rf'"{re.escape(f)}"\s*:\s*(?:"?admin|true|\d|\[)', resp_text, re.I):
            out.append(f)
    return out


def _similar_json(text: str) -> bool:
    obj = safe_json_loads(text)
    return isinstance(obj, (dict, list)) and len(text) > 8


def _swap_url(tx: dict, path: str, query: str) -> str:
    host = tx.get("host")
    port = tx.get("port") or 443
    scheme = tx.get("scheme") or "https"
    q = f"?{query}" if query else ""
    default = (scheme == "https" and port in (443, 0)) or (scheme == "http" and port in (80, 0))
    netloc = host if default else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}{q}"


def _headers_with(headers: list[tuple[str, str]] | dict[str, str], name: str, value: str) -> dict[str, str]:
    if isinstance(headers, list):
        d = {k: v for k, v in headers}
    else:
        d = dict(headers)
    for k in list(d.keys()):
        if k.lower() == name.lower():
            del d[k]
    d[name] = value
    return d


def _jwt_set_claim(token: str, claim: str, value: Any) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        obj = json.loads(base64.urlsafe_b64decode(payload))
        obj[claim] = value
        new_payload = base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
        return f"{parts[0]}.{new_payload}.{parts[2]}"
    except Exception:  # noqa: BLE001
        return None


MUTATORS: dict[str, Callable[[ActiveContext, dict], list[dict[str, Any]]]] = {
    "iterate_object_id": mutate_iterate_object_id,
    "mass_assign": mutate_mass_assign,
    "probe_field_permissions": mutate_probe_field_permissions,
    "burst": mutate_burst,
    "admin_path_swap": mutate_admin_path_swap,
    "ssrf_url_param": mutate_ssrf_url_param,
    "logout_replay": mutate_logout_replay,
    "replay_with_expired_claims": mutate_replay_with_expired_claims,
}


def replay_request(store: TrafficStore, tx_id: str, **kwargs: Any) -> httpx.Response | None:
    """Standalone replay helper (used by `iostester replay` CLI command)."""
    ctx = ActiveContext(store=store, session_name="replay", **{k: v for k, v in kwargs.items() if k in ("allow_hosts", "delay")})
    rec = store.replay_record(tx_id)
    if not rec:
        return None
    return ctx.send(rec, **{k: v for k, v in kwargs.items() if k in ("method", "url", "headers", "content")})
