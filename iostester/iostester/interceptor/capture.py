"""Traffic store & HTTP stream splitter.

This is the heart of Phase 3: raw plaintext bytes captured by the Frida agent
are split into HTTP transactions and persisted to SQLite.

Two protocol splitters are provided:

* H1Splitter -- HTTP/1.1 via `h11`
* H2Splitter -- HTTP/2 (the dominant protocol on iOS) via `hyperframe` + `hpack`

Both feed a TrafficStore which writes rows into `traffic.sqlite` in the
session directory. The store is the single source of truth for later phases
(scan / reports / replay / dashboard).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import h11
import hpack
import hyperframe.frame as hf

from ..core.util import b64e, decode_body, now_iso, normalize_path_template

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id             TEXT PRIMARY KEY,
    conn_id           TEXT NOT NULL,
    session           TEXT,
    ts                REAL,
    scheme            TEXT,
    host              TEXT,
    port              INTEGER,
    method            TEXT,
    path              TEXT,
    query             TEXT,
    http_version      TEXT,
    req_headers       TEXT,
    req_body          BLOB,
    req_body_len      INTEGER DEFAULT 0,
    req_ts            REAL,
    status            INTEGER,
    resp_http_version TEXT,
    resp_headers      TEXT,
    resp_body          BLOB,
    resp_body_len     INTEGER DEFAULT 0,
    resp_ts           REAL,
    elapsed_ms        REAL,
    server_addr       TEXT,
    client_addr       TEXT,
    error             TEXT,
    note              TEXT
);

CREATE INDEX IF NOT EXISTS idx_tx_host   ON transactions(host);
CREATE INDEX IF NOT EXISTS idx_tx_method ON transactions(method);
CREATE INDEX IF NOT EXISTS idx_tx_path   ON transactions(path);
CREATE INDEX IF NOT EXISTS idx_tx_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_tx_ts     ON transactions(ts);

CREATE TABLE IF NOT EXISTS conns (
    conn_id   TEXT PRIMARY KEY,
    session   TEXT,
    host      TEXT,
    port      INTEGER,
    proto     TEXT,
    fd        INTEGER,
    peer      TEXT,
    opened_at REAL,
    closed_at REAL
);
"""


@dataclass
class RequestRecord:
    """A captured request, sufficient to replay it with modifications."""

    tx_id: str
    method: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    http_version: str
    headers: list[tuple[str, str]]
    body: bytes | None
    ts: float

    @property
    def url(self) -> str:
        q = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{self.host}:{self.port}{self.path}{q}"

    @property
    def url_no_port(self) -> str:
        q = f"?{self.query}" if self.query else ""
        default = (self.scheme == "https" and self.port in (443, 0)) or (
            self.scheme == "http" and self.port in (80, 0)
        )
        netloc = self.host if default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}{q}"


def _hdr_json(h: list[tuple[str, str]] | None) -> str | None:
    return json.dumps(h) if h is not None else None


class TrafficStore:
    """SQLite-backed structured traffic store (thread-safe via one lock)."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_SCHEMA)
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('created_at', ?)",
            (now_iso(),),
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # writes
    # ------------------------------------------------------------------
    def register_conn(
        self,
        conn_id: str,
        session: str,
        host: str,
        port: int,
        proto: str,
        fd: int | None = None,
        peer: str | None = None,
    ) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO conns (conn_id, session, host, port, proto, fd, peer, opened_at) "
                "VALUES (?,?,?,?,?,?,?, COALESCE((SELECT opened_at FROM conns WHERE conn_id=?), ?))",
                (conn_id, session, host, port, proto, fd, peer, conn_id, time.time()),
            )
            self.conn.commit()

    def close_conn(self, conn_id: str, proto: str | None = None) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE conns SET closed_at=? WHERE conn_id=?", (time.time(), conn_id)
            )
            if proto:
                self.conn.execute("UPDATE conns SET proto=? WHERE conn_id=?", (proto, conn_id))
            self.conn.commit()

    def set_conn_proto(self, conn_id: str, proto: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE conns SET proto=? WHERE conn_id=?", (proto, conn_id))
            self.conn.commit()

    def start_tx(
        self,
        tx_id: str,
        conn_id: str,
        session: str,
        scheme: str,
        host: str,
        port: int,
        server_addr: str | None,
        note: str | None = None,
    ) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO transactions "
                "(tx_id, conn_id, session, ts, scheme, host, port, server_addr, note) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (tx_id, conn_id, session, time.time(), scheme, host, port, server_addr, note),
            )
            self.conn.commit()

    def set_request(
        self,
        tx_id: str,
        method: str,
        path: str,
        query: str,
        http_version: str,
        headers: list[tuple[str, str]],
        body: bytes | None,
        ts: float | None = None,
    ) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE transactions SET method=?, path=?, query=?, http_version=?, req_headers=?, "
                "req_body=?, req_body_len=?, req_ts=? WHERE tx_id=?",
                (
                    method,
                    path,
                    query,
                    http_version,
                    _hdr_json(headers),
                    body,
                    len(body) if body else 0,
                    ts if ts is not None else time.time(),
                    tx_id,
                ),
            )
            self.conn.commit()

    def set_response(
        self,
        tx_id: str,
        status: int,
        http_version: str,
        headers: list[tuple[str, str]],
        body: bytes | None,
        ts: float | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE transactions SET status=?, resp_http_version=?, resp_headers=?, "
                "resp_body=?, resp_body_len=?, resp_ts=?, error=? WHERE tx_id=?",
                (
                    status,
                    http_version,
                    _hdr_json(headers),
                    body,
                    len(body) if body else 0,
                    ts if ts is not None else time.time(),
                    error,
                    tx_id,
                ),
            )
            self.conn.commit()

    def set_error(self, tx_id: str, error: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE transactions SET error=? WHERE tx_id=?", (error, tx_id))
            self.conn.commit()

    def finalize(self, tx_id: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE transactions SET elapsed_ms = (COALESCE(resp_ts, ts) - COALESCE(req_ts, ts)) * 1000 "
                "WHERE tx_id=?",
                (tx_id,),
            )
            self.conn.commit()

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------
    def get(self, tx_id: str, decode: bool = True) -> dict[str, Any] | None:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM transactions WHERE tx_id=?", (tx_id,))
            row = cur.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cur.description]
        return self._row_to_dict(cols, row, decode=decode)

    def iter_transactions(
        self,
        host: str | None = None,
        method: str | None = None,
        path_like: str | None = None,
        status: int | None = None,
        status_gte: int | None = None,
        exclude_empty_hosts: bool = True,
        limit: int | None = None,
        order: str = "ts",
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM transactions WHERE 1=1"
        args: list[Any] = []
        if host:
            sql += " AND host = ?"
            args.append(host)
        if method:
            sql += " AND UPPER(method) = UPPER(?)"
            args.append(method)
        if path_like:
            sql += " AND path LIKE ?"
            args.append(f"%{path_like}%")
        if status is not None:
            sql += " AND status = ?"
            args.append(status)
        if status_gte is not None:
            sql += " AND status >= ?"
            args.append(status_gte)
        if exclude_empty_hosts:
            sql += " AND method IS NOT NULL"
        sql += f" ORDER BY {order}"
        if limit:
            sql += f" LIMIT {int(limit)}"
        with self._lock:
            cur = self.conn.execute(sql, args)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
        return [self._row_to_dict(cols, r, decode=True) for r in rows]

    def _row_to_dict(self, cols: list[str], row, decode: bool = True) -> dict[str, Any]:
        d = dict(zip(cols, row))
        for k in ("req_headers", "resp_headers"):
            try:
                d[k] = json.loads(d[k]) if d[k] else []
            except Exception:  # noqa: BLE001
                d[k] = []
        if decode:
            rb = d.get("resp_body")
            if rb is not None:
                dec, note = decode_body(d.get("resp_headers") or [], rb)
                d["resp_body_decoded"] = dec
                if note:
                    d["resp_body_note"] = note
        d["body_type"] = _body_type(d.get("resp_headers") or [], d.get("resp_body"))
        return d

    def replay_record(self, tx_id: str) -> RequestRecord | None:
        d = self.get(tx_id, decode=False)
        if not d or not d.get("method"):
            return None
        return RequestRecord(
            tx_id=tx_id,
            method=d["method"],
            scheme=d.get("scheme") or "https",
            host=d["host"],
            port=d.get("port") or 443,
            path=d.get("path") or "/",
            query=d.get("query") or "",
            http_version=d.get("http_version") or "HTTP/1.1",
            headers=[(h[0], h[1]) for h in (d.get("req_headers") or [])],
            body=d.get("req_body"),
            ts=d.get("req_ts") or d.get("ts") or 0.0,
        )

    def stats(self) -> dict[str, Any]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT host), COUNT(DISTINCT path), "
                "SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) FROM transactions WHERE method IS NOT NULL"
            )
            count, hosts, paths, errs = cur.fetchone()
            cur = self.conn.execute("SELECT COUNT(*) FROM conns")
            conns = cur.fetchone()[0]
        return {
            "transactions": count or 0,
            "hosts": hosts or 0,
            "paths": paths or 0,
            "errors_4xx_5xx": errs or 0,
            "connections": conns or 0,
        }

    def host_summary(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT host, COUNT(*) as n, COUNT(DISTINCT path) as paths, "
                "MAX(ts) as last_seen FROM transactions WHERE method IS NOT NULL "
                "GROUP BY host ORDER BY n DESC"
            )
            rows = cur.fetchall()
        return [
            {"host": r[0], "transactions": r[1], "paths": r[2], "last_seen": r[3]} for r in rows
        ]

    def endpoint_summary(self, exclude_hosts: Iterable[str] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT host, path, method, COUNT(*) as n, AVG(elapsed_ms) as avg_ms, "
                "MIN(status) as min_st, MAX(status) as max_st "
                "FROM transactions WHERE method IS NOT NULL GROUP BY host, path, method ORDER BY n DESC"
            )
            rows = cur.fetchall()
        ex = set(exclude_hosts)
        out = []
        for host, path, method, n, avg_ms, min_st, max_st in rows:
            if host in ex:
                continue
            out.append(
                {
                    "host": host,
                    "path": path,
                    "method": method,
                    "template": normalize_path_template(path or "/"),
                    "count": n,
                    "avg_ms": avg_ms,
                    "min_status": min_st,
                    "max_status": max_st,
                }
            )
        return out

    def close(self) -> None:
        with self._lock:
            self.conn.commit()
            self.conn.close()


def _has_flag(frame: hf.Frame, name: str) -> bool:
    if hasattr(frame, "flags"):
        f = frame.flags
        if isinstance(f, (set, list, tuple)) or type(f).__name__ == "Flags":
            return name in f
        if isinstance(f, int):
            bit = 0x1 if name == "END_STREAM" else (0x4 if name == "END_HEADERS" else 0)
            return bool(f & bit)
    return False


def _body_type(headers: list[list[str]], body: bytes | None) -> str:
    if body is None:
        return "none"
    ct = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ct = v.lower()
            break
    if "json" in ct:
        return "json"
    if "x-www-form-urlencoded" in ct:
        return "form"
    if "text/" in ct or "xml" in ct or "javascript" in ct:
        return "text"
    if "octet-stream" in ct or "image" in ct or "font" in ct or "protobuf" in ct:
        return "binary"
    # sniff
    if body[:1] in (b"{", b"["):
        return "json"
    try:
        body[:512].decode("utf-8")
        return "text"
    except Exception:  # noqa: BLE001
        return "binary"


# ---------------------------------------------------------------------------
# HTTP splitter base + implementations
# ---------------------------------------------------------------------------


class BaseSplitter:
    """Splits one connection's plaintext streams into transactions."""

    def __init__(
        self,
        store: TrafficStore,
        session: str,
        conn_id: str,
        host: str,
        port: int,
        scheme: str = "https",
        server_addr: str | None = None,
        direction: str = "upstream",
    ):
        self.store = store
        self.session = session
        self.conn_id = conn_id
        self.host = host
        self.port = port
        self.scheme = scheme
        self.server_addr = server_addr
        self.direction = direction  # 'upstream' (host side) or 'generic'
        self._txn = 0
        self.on_tx_complete: Optional[Callable[[str], None]] = None

    def next_tx_id(self) -> str:
        self._txn += 1
        return f"{self.conn_id}:{self._txn}"

    def feed_request(self, data: bytes) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def feed_response(self, data: bytes) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def flush(self) -> None:
        pass


class H1Splitter(BaseSplitter):
    """HTTP/1.1 splitter (h11 based)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._req_conn = h11.Connection(h11.SERVER)
        self._resp_conn = h11.Connection(h11.CLIENT)
        self._cur_tx: str | None = None
        self._req_chunks: list[bytes] = []
        self._resp_chunks: list[bytes] = []

    # upstream: bytes the app SENT (requests)
    def feed_request(self, data: bytes) -> None:
        if not data:
            return
        try:
            self._req_conn.receive_data(data)
        except Exception as exc:  # noqa: BLE001
            if self._cur_tx:
                self.store.set_error(self._cur_tx, f"h1 request parse error: {exc}")
            return
        while True:
            try:
                ev = self._req_conn.next_event()
            except Exception as exc:  # noqa: BLE001
                if self._cur_tx:
                    self.store.set_error(self._cur_tx, f"h1 request parse error: {exc}")
                break
            if ev is h11.NEED_DATA or ev is h11.PAUSED:
                break
            if isinstance(ev, h11.Request):
                self._cur_tx = self.next_tx_id()
                target = ev.target.decode("utf-8", "replace")
                path, _, query = target.partition("?")
                self.store.start_tx(
                    self._cur_tx, self.conn_id, self.session, self.scheme, self.host, self.port,
                    self.server_addr,
                )
                self.store.set_request(
                    self._cur_tx,
                    ev.method.decode("ascii", "replace"),
                    path,
                    query,
                    "HTTP/1.1",
                    [(k.decode("latin1"), v.decode("latin1")) for k, v in ev.headers],
                    None,
                )
                self._req_chunks = []
            elif isinstance(ev, h11.Data):
                if self._cur_tx:
                    self._req_chunks.append(bytes(ev.data))
            elif isinstance(ev, h11.EndOfMessage):
                if self._cur_tx:
                    body = b"".join(self._req_chunks) if self._req_chunks else None
                    with self.store._lock:  # noqa: SLF001 - internal update of body only
                        self.store.conn.execute(
                            "UPDATE transactions SET req_body=?, req_body_len=? WHERE tx_id=?",
                            (body, len(body) if body else 0, self._cur_tx),
                        )
                        self.store.conn.commit()
                    self._req_chunks = []
            elif isinstance(ev, h11.ConnectionClosed):
                break
        self._req_conn.start_next_cycle() if self._req_conn.our_state is h11.DONE else None

    # downstream: bytes the app RECEIVED (responses)
    def feed_response(self, data: bytes) -> None:
        if not data:
            return
        try:
            self._resp_conn.receive_data(data)
        except Exception as exc:  # noqa: BLE001
            if self._cur_tx:
                self.store.set_error(self._cur_tx, f"h1 response parse error: {exc}")
            return
        while True:
            try:
                ev = self._resp_conn.next_event()
            except Exception as exc:  # noqa: BLE001
                if self._cur_tx:
                    self.store.set_error(self._cur_tx, f"h1 response parse error: {exc}")
                break
            if ev is h11.NEED_DATA or ev is h11.PAUSED:
                break
            if isinstance(ev, h11.InformationalResponse):
                continue
            if isinstance(ev, h11.Response):
                if not self._cur_tx:
                    continue
                self._resp_chunks = []
                self.store.set_response(
                    self._cur_tx,
                    ev.status_code,
                    "HTTP/1.1",
                    [(k.decode("latin1"), v.decode("latin1")) for k, v in ev.headers],
                    None,
                )
            elif isinstance(ev, h11.Data):
                if self._cur_tx:
                    self._resp_chunks.append(bytes(ev.data))
            elif isinstance(ev, h11.EndOfMessage):
                if self._cur_tx:
                    body = b"".join(self._resp_chunks) if self._resp_chunks else None
                    with self.store._lock:  # noqa: SLF001
                        self.store.conn.execute(
                            "UPDATE transactions SET resp_body=?, resp_body_len=? WHERE tx_id=?",
                            (body, len(body) if body else 0, self._cur_tx),
                        )
                        self.store.conn.commit()
                    self.store.finalize(self._cur_tx)
                    if self.on_tx_complete:
                        self.on_tx_complete(self._cur_tx)
                    self._resp_chunks = []
            elif isinstance(ev, h11.ConnectionClosed):
                break
        if self._resp_conn.our_state is h11.DONE:
            try:
                self._resp_conn.start_next_cycle()
            except Exception:  # noqa: BLE001
                pass


class H2Splitter(BaseSplitter):
    """HTTP/2 splitter (hyperframe + hpack)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._up_buf = bytearray()
        self._down_buf = bytearray()
        self._req_dec = hpack.Decoder()
        self._resp_dec = hpack.Decoder()
        self._streams: dict[int, dict[str, Any]] = {}
        # CONTINUATION handling: (buffer, side, stream_id, frame_meta)
        self._cont_up: dict[str, Any] | None = None
        self._cont_down: dict[str, Any] | None = None

    # ---- helpers -----------------------------------------------------
    @staticmethod
    def _parse_frames(buf: bytearray) -> list[hf.Frame]:
        frames = []
        while len(buf) >= 9:
            try:
                frame, length = hf.Frame.parse_frame_header(memoryview(buf[:9]))
            except Exception:
                del buf[:1]
                continue
            if len(buf) < 9 + length:
                break
            body = bytes(buf[9 : 9 + length])
            try:
                frame.parse_body(memoryview(body))
                frames.append(frame)
            except Exception:
                pass
            del buf[: 9 + length]
        return frames

    @staticmethod
    def _pseudo_split(raw_headers: list[tuple[Any, Any]]) -> tuple[dict[str, str], list[tuple[str, str]]]:
        pseudo: dict[str, str] = {}
        norm: list[tuple[str, str]] = []
        for k, v in raw_headers:
            ks = k.decode("latin1") if isinstance(k, (bytes, bytearray)) else str(k)
            vs = v.decode("latin1") if isinstance(v, (bytes, bytearray)) else str(v)
            if ks.startswith(":"):
                pseudo[ks] = vs
            else:
                norm.append((ks, vs))
        return pseudo, norm

    # ---- upstream (requests) ------------------------------------------
    def feed_request(self, data: bytes) -> None:
        if not data:
            return
        self._up_buf.extend(data)
        for frame in self._parse_frames(self._up_buf):
            self._on_up_frame(frame)

    def _on_up_frame(self, frame: hf.Frame) -> None:
        # -- CONTINUATION bookkeeping ------------------------------------
        if self._cont_up is not None:
            if isinstance(frame, hf.ContinuationFrame) and frame.stream_id == self._cont_up["sid"]:
                self._cont_up["data"].extend(frame.data or b"")
                if _has_flag(frame, "END_HEADERS"):
                    self._flush_cont_up()
                return
            # unexpected frame while waiting for CONTINUATION: flush what we have
            self._flush_cont_up()
        if isinstance(frame, hf.HeadersFrame) and not _has_flag(frame, "END_HEADERS"):
            self._cont_up = {"sid": frame.stream_id, "data": bytearray(frame.data or b"")}
            return

        if isinstance(frame, hf.HeadersFrame):
            hdrs: list[tuple[bytes, bytes]] = []
            try:
                hdrs = self._req_dec.decode(frame.data or b"")
            except Exception:  # noqa: BLE001
                hdrs = []
            self._emit_request(frame.stream_id, hdrs)
        elif isinstance(frame, hf.DataFrame):
            st = self._streams.get(frame.stream_id)
            if st and frame.data is not None:
                st["body"].append(frame.data)
        else:
            return
        if isinstance(frame, (hf.HeadersFrame, hf.DataFrame)) and _has_flag(frame, "END_STREAM"):
            st = self._streams.get(frame.stream_id)
            if st and not st.get("completed"):
                st["completed"] = True
                body = b"".join(st["body"]) if st["body"] else None
                with self.store._lock:  # noqa: SLF001
                    self.store.conn.execute(
                        "UPDATE transactions SET req_body=?, req_body_len=? WHERE tx_id=?",
                        (body, len(body) if body else 0, st["tx"]),
                    )
                    self.store.conn.commit()

    def _flush_cont_up(self) -> None:
        pending, self._cont_up = self._cont_up, None
        if not pending:
            return
        try:
            hdrs = self._req_dec.decode(bytes(pending["data"]))
        except Exception:  # noqa: BLE001
            hdrs = []
        self._emit_request(pending["sid"], hdrs)

    def _flush_cont_down(self) -> None:
        pending, self._cont_down = self._cont_down, None
        if not pending:
            return
        try:
            hdrs = self._resp_dec.decode(bytes(pending["data"]))
        except Exception:  # noqa: BLE001
            hdrs = []
        self._emit_response(pending["sid"], hdrs)

    def _emit_request(self, stream_id: int, hdrs: list[tuple[bytes, bytes]]) -> None:
        pseudo, norm = self._pseudo_split(hdrs)
        tid = self.next_tx_id()
        path = pseudo.get(":path", "/")
        p, _, q = path.partition("?")
        host = self.host
        if pseudo.get(":authority"):
            host = pseudo[":authority"].split(":")[0]
        self.store.start_tx(tid, self.conn_id, self.session, self.scheme, host, self.port, self.server_addr)
        self.store.set_request(tid, pseudo.get(":method", "GET"), p, q, "HTTP/2", norm, None)
        self._streams[stream_id] = {"tx": tid, "body": [], "completed": False, "resp_chunks": []}

    def _emit_response(self, stream_id: int, hdrs: list[tuple[bytes, bytes]]) -> None:
        pseudo, norm = self._pseudo_split(hdrs)
        st = self._streams.get(stream_id)
        if not st:
            return
        try:
            status = int(pseudo.get(":status", "0"))
        except ValueError:
            status = 0
        self.store.set_response(st["tx"], status, "HTTP/2", norm, None)
        st["resp_chunks"] = []

    # ---- downstream (responses) ---------------------------------------
    def feed_response(self, data: bytes) -> None:
        if not data:
            return
        self._down_buf.extend(data)
        for frame in self._parse_frames(self._down_buf):
            self._on_down_frame(frame)

    def _on_down_frame(self, frame: hf.Frame) -> None:
        if self._cont_down is not None:
            if isinstance(frame, hf.ContinuationFrame) and frame.stream_id == self._cont_down["sid"]:
                self._cont_down["data"].extend(frame.data or b"")
                if _has_flag(frame, "END_HEADERS"):
                    self._flush_cont_down()
                return
            self._flush_cont_down()
        if isinstance(frame, hf.HeadersFrame) and not _has_flag(frame, "END_HEADERS"):
            self._cont_down = {"sid": frame.stream_id, "data": bytearray(frame.data or b"")}
            return

        if isinstance(frame, hf.HeadersFrame):
            hdrs: list[tuple[bytes, bytes]] = []
            try:
                hdrs = self._resp_dec.decode(frame.data or b"")
            except Exception:  # noqa: BLE001
                hdrs = []
            self._emit_response(frame.stream_id, hdrs)
        elif isinstance(frame, hf.DataFrame):
            st = self._streams.get(frame.stream_id)
            if st and frame.data is not None:
                st.setdefault("resp_chunks", []).append(frame.data)
        else:
            return
        if isinstance(frame, (hf.HeadersFrame, hf.DataFrame)) and _has_flag(frame, "END_STREAM"):
            st = self._streams.get(frame.stream_id)
            if st and not st.get("resp_done"):
                st["resp_done"] = True
                body = b"".join(st.get("resp_chunks") or []) or None
                with self.store._lock:  # noqa: SLF001
                    self.store.conn.execute(
                        "UPDATE transactions SET resp_body=?, resp_body_len=? WHERE tx_id=?",
                        (body, len(body) if body else 0, st["tx"]),
                    )
                    self.store.conn.commit()
                self.store.finalize(st["tx"])
                if self.on_tx_complete:
                    self.on_tx_complete(st["tx"])
                self._streams.pop(frame.stream_id, None)


def make_splitter(proto: str, *args, **kwargs) -> BaseSplitter:
    return H2Splitter(*args, **kwargs) if proto == "h2" else H1Splitter(*args, **kwargs)
