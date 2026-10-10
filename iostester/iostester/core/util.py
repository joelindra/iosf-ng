"""Core utilities: shared helpers used across iostester modules."""
from __future__ import annotations

import base64
import gzip
import json
import math
import re
import zlib
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def sha1_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha1(data).hexdigest()


def human_bytes(n: int | float | None) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} GB"


def shannon_entropy(data: str | bytes) -> float:
    if isinstance(data, str):
        data = data.encode("utf-8", "ignore")
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "apikey",
    "x-access-token",
    "proxy-authorization",
}

REDACTED = "[REDACTED]"


def redact_value(value: str, keep: int = 6) -> str:
    if not value:
        return value
    if keep <= 0 or len(value) <= keep:
        return REDACTED
    return value[:keep] + "..." + REDACTED


def headers_to_list(headers: Iterable[tuple[str, str]]) -> list[list[str]]:
    return [[k, v] for k, v in headers]


def headers_from_list(headers: Sequence[Sequence[str]] | None) -> list[tuple[str, str]]:
    if not headers:
        return []
    return [(h[0], h[1]) for h in headers if len(h) == 2]


def get_header(headers: Sequence[Sequence[str]], name: str) -> str | None:
    lname = name.lower()
    for k, v in headers_from_list(headers):
        if k.lower() == lname:
            return v
    return None


def redact_headers(headers: Sequence[Sequence[str]] | None) -> list[list[str]]:
    out = []
    for k, v in headers_from_list(headers):
        if k.lower() in SENSITIVE_HEADERS:
            # keep scheme/prefix for evidence value while redacting the secret
            if k.lower() in ("authorization",):
                parts = v.split(" ", 1)
                v = parts[0] + " " + REDACTED if len(parts) == 2 else REDACTED
            else:
                v = redact_value(v, keep=0)
        out.append([k, v])
    return out


def decode_body(headers: Sequence[Sequence[str]] | None, body: bytes | None) -> tuple[bytes | None, str | None]:
    """Decode a captured body according to its Content-Encoding.

    Returns (decoded_body, error_note). If decoding fails or is unsupported,
    the raw body is returned with an explanatory note.
    """
    if body is None:
        return None, None
    enc = (get_header(headers or [], "content-encoding") or "").lower().strip()
    if not enc or enc == "identity":
        return body, None
    try:
        if enc == "gzip":
            return gzip.decompress(body), None
        if enc == "deflate":
            try:
                return zlib.decompress(body), None
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), None
        if enc in ("br",):
            try:
                import brotli  # type: ignore

                return brotli.decompress(body), None
            except Exception:
                return body, "brotli not installed; body left encoded"
        if enc == "zstd":
            try:
                import zstandard  # type: ignore

                return zstandard.ZstdDecompressor().decompress(body), None
            except Exception:
                return body, "zstandard not installed; body left encoded"
    except Exception as exc:  # noqa: BLE001
        return body, f"decode failed ({type(exc).__name__}); body left encoded"
    return body, f"unsupported content-encoding: {enc}"


def truncate_body(body: bytes | None, limit: int) -> tuple[bytes | None, bool]:
    if body is None:
        return None, False
    if len(body) > limit:
        return body[:limit], True
    return body, False


_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONGHEX_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_NUM_RE = re.compile(r"/\d{1,12}(?=/|$)")


def normalize_path_template(path: str) -> str:
    """Collapse identifiers in paths so findings dedupe cleanly."""
    p = path.split("?")[0]
    p = _UUID_RE.sub("/{uuid}", p)
    p = _NUM_RE.sub("/{id}", p)
    p = _LONGHEX_RE.sub("{hex}", p)
    return p


def path_id_candidates(path: str, query: str) -> list[tuple[str, str]]:
    """Find numeric identifiers in path or query for BOLA style probing.

    Returns list of (location, value) where location is 'path' or 'query'.
    """
    out: list[tuple[str, str]] = []
    for m in re.finditer(r"/(\d{1,12})(?=/|$)", path):
        out.append(("path", m.group(1)))
    for m in re.finditer(r"(?:[?&])([A-Za-z0-9_\-\[\]\.]+)=(\d{1,12})(?=&|$)", "?" + query if query else ""):
        out.append(("query", m.group(2)))
    return out


def safe_json_loads(data: bytes | str | None) -> Any:
    if data is None:
        return None
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        return json.loads(data)
    except Exception:  # noqa: BLE001
        return None


def is_json_content_type(ct: str | None) -> bool:
    return bool(ct) and ("json" in ct.lower())


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out
