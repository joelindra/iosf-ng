"""Frida-based live TLS interceptor (Phase 3).

Drives `ios_tls_agent.js` inside the target app process and turns its
streamed plaintext slices into structured transactions in the session store.

Two deployment modes:

* **jailbreak / dev mode** (`mode=spawn|attach`): Frida server on a
  jailbroken device (e.g. Dopamine on checkm8 hardware), or a debug build
  with get-task-allow. CLI: `iostester intercept`.
* **gadget mode** (`mode=gadget`): attach to a Frida Gadget injected into a
  resigned IPA (`iostester inject --gadget`) listening on a local port that
  is forwarded from the device via usbmux. This is the non-jailbreak path.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from ..core.util import now_iso
from .capture import H1Splitter, H2Splitter, TrafficStore

AGENT_JS = Path(__file__).resolve().parent.parent / "agent" / "ios_tls_agent.js"

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"PATCH ",
    b"OPTIONS ",
    b"CONNECT ",
    b"TRACE ",
)


@dataclass
class CaptureOptions:
    session_name: str
    bundle_id: str | None = None
    pid: int | None = None
    host_filter: list[str] = field(default_factory=list)
    capture_body: bool = True
    max_slice: int = 262144
    serial: str | None = None
    gadget_host: str | None = None  # e.g. tcp from usbmux forward
    spawn_timeout: float = 15.0


class ConnectionState:
    __slots__ = (
        "conn_id",
        "host",
        "port",
        "fd",
        "peer",
        "proto",
        "splitter",
        "first_buf",
        "down_buf",
        "bytes_up",
        "bytes_down",
        "transactions",
    )

    def __init__(self, conn_id: str):
        self.conn_id = conn_id
        self.host: str | None = None
        self.port = 443
        self.fd: int | None = None
        self.peer: str | None = None
        self.proto: str | None = None
        self.splitter: H1Splitter | H2Splitter | None = None
        self.first_buf = bytearray()
        self.down_buf = bytearray()
        self.bytes_up = 0
        self.bytes_down = 0
        self.transactions = 0


class FridaCapture:
    """Runs the agent and persists captured traffic. Thread-safe."""

    def __init__(
        self,
        store: TrafficStore,
        opts: CaptureOptions,
        on_tx: Optional[Callable[[str], None]] = None,
        log: Optional[Callable[[str], None]] = None,
    ):
        self.store = store
        self.opts = opts
        self.on_tx = on_tx
        self.log = log or (lambda m: None)

        self._conns: dict[str, ConnectionState] = {}
        self._lock = threading.RLock()
        self._dev = None
        self._session = None
        self._script = None
        self._spawned_pid: int | None = None
        self._stop = threading.Event()
        self.agent_stats: dict[str, int] = {}
        self.dns_hosts: list[str] = []
        self.host_stats: dict[str, int] = {}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def load_agent_source(self) -> str:
        src = AGENT_JS.read_text(encoding="utf-8")
        cfg = {
            "hosts": self.opts.host_filter,
            "captureBody": self.opts.capture_body,
            "maxSlice": self.opts.max_slice,
        }
        return src.replace("'__CFG__' || '{}'", json.dumps(json.dumps(cfg)))

    def start(self) -> None:
        import frida

        if self.opts.gadget_host:
            mgr = frida.get_device_manager()
            self._dev = mgr.add_remote_device(self.opts.gadget_host)
            self.log(f"gadget device: {self.opts.gadget_host}")
            target = self._find_gadget_process()
            if isinstance(target, int):
                self._session = self._dev.attach(target)
                self.log(f"attached to gadget pid {target}")
            else:
                self._session = self._dev.attach(target)
                self.log(f"attached to gadget process {target}")
        else:
            self._dev = self._pick_usb_device()
            device_desc = f"{self._dev.name}"
            if self.opts.pid:
                self._session = self._dev.attach(self.opts.pid)
                self.log(f"attached pid {self.opts.pid} on {device_desc}")
            elif self.opts.bundle_id:
                pid = self._dev.spawn([self.opts.bundle_id])
                self._spawned_pid = pid
                self._session = self._dev.attach(pid)
                self.log(f"spawned {self.opts.bundle_id} -> pid {pid} on {device_desc}")
            else:
                raise ValueError("Provide --pid or --app <bundle_id> (or --gadget-host)")

        self._session.on("detached", self._on_detached)
        script = self._session.create_script(self.load_agent_source())
        script.on("message", self._on_message)
        script.load()
        self._script = script

        if self._spawned_pid is not None:
            self._dev.resume(self._spawned_pid)
            self.log("resumed target process")

    def _find_gadget_process(self):
        """Pick the app process in gadget mode (largest non-system process)."""
        procs = self._dev.enumerate_processes()
        cand = [p for p in procs if p.name and not p.name.startswith(("launchd", "frida"))]
        # gadget device typically exposes one app process
        if not cand:
            raise RuntimeError("No attachable process on gadget device")
        cand.sort(key=lambda p: p.pid)
        return cand[0].pid

    def _pick_usb_device(self):
        import frida

        mgr = frida.get_device_manager()
        devs = [d for d in mgr.enumerate_devices() if d.type == "usb"]
        if not devs:
            raise RuntimeError(
                "No USB iOS device found by Frida. Is the device paired and "
                "frida-server (jailbreak) or Gadget (non-jailbreak) running?"
            )
        if self.opts.serial:
            for d in devs:
                if self.opts.serial.lower() in (d.name or "").lower():
                    return d
        return devs[0]

    def stop(self) -> None:
        self._stop.set()
        if self._script is not None:
            try:
                self._script.unload()
            except Exception:  # noqa: BLE001
                pass
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:  # noqa: BLE001
                pass
        if self._spawned_pid is not None and self._dev is not None:
            try:
                self._dev.kill(self._spawned_pid)
            except Exception:  # noqa: BLE001
                pass

    def run_forever(self, duration: float | None = None, poll: float = 0.5) -> None:
        started = time.time()
        try:
            while not self._stop.is_set():
                if duration and time.time() - started >= duration:
                    break
                time.sleep(poll)
        except KeyboardInterrupt:
            self.log("interrupted by user")

    # ------------------------------------------------------------------
    # message handling
    # ------------------------------------------------------------------
    def _on_detached(self, reason: str, *args) -> None:
        self.log(f"session detached: {reason}")

    def _on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        if message.get("type") == "error":
            self.log(f"agent error: {message.get('description')}")
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, str):
            return
        try:
            msg = json.loads(payload)
        except Exception:  # noqa: BLE001
            return
        t = msg.get("t")
        try:
            if t == "agent":
                self.log(f"agent: {msg.get('kind')} (pid={msg.get('pid')}, arch={msg.get('arch')})")
            elif t == "conn_open":
                self._on_conn_open(msg)
            elif t == "data":
                self._on_data(msg)
            elif t == "dns":
                host = msg.get("host")
                if host and host not in self.dns_hosts:
                    self.dns_hosts.append(host)
            elif t == "stats":
                self.agent_stats = msg.get("stats") or {}
        except Exception as exc:  # noqa: BLE001
            self.log(f"dispatch error on {t}: {exc}")

    def _on_conn_open(self, msg: dict[str, Any]) -> None:
        conn_id = msg.get("conn") or f"c{len(self._conns)+1}"
        with self._lock:
            st = self._conns.setdefault(conn_id, ConnectionState(conn_id))
            host = msg.get("host")
            if host:
                st.host = _norm_host(host)
            if msg.get("peer"):
                st.peer = msg["peer"]
            if msg.get("fd") is not None:
                st.fd = msg.get("fd")

    def _on_data(self, msg: dict[str, Any]) -> None:
        conn_id = msg.get("conn")
        direction = msg.get("dir")
        hexdata = msg.get("hex") or ""
        if not conn_id or not hexdata:
            return
        data = bytes.fromhex(hexdata)
        with self._lock:
            st = self._conns.setdefault(conn_id, ConnectionState(conn_id))
            host = msg.get("host")
            if host:
                st.host = _norm_host(host)
            if msg.get("peer"):
                st.peer = msg["peer"]
            if direction == "up":
                st.bytes_up += len(data)
                self._feed_up(st, data)
            elif direction == "down":
                st.bytes_down += len(data)
                self._feed_down(st, data)
        hs = st.host or (st.peer or "unknown")
        self.host_stats[hs] = self.host_stats.get(hs, 0) + 1

    # ---- splitting -------------------------------------------------------
    def _ensure_conn_row(self, st: ConnectionState) -> None:
        if st.proto and st.host:
            self.store.register_conn(
                st.conn_id,
                self.opts.session_name,
                st.host,
                st.port,
                st.proto,
                fd=st.fd,
                peer=st.peer,
            )

    def _detect_proto(self, st: ConnectionState) -> bool:
        buf = st.first_buf
        if st.proto:
            return True
        if buf.startswith(H2_PREFACE[: min(len(buf), len(H2_PREFACE))]):
            if len(buf) >= len(H2_PREFACE):
                st.proto = "h2"
                rest = bytes(buf[len(H2_PREFACE) :])
                buf.clear()
                self._make_splitter(st)
                self._ensure_conn_row(st)
                if rest:
                    st.splitter.feed_request(rest)
                return True
            return False
        # not h2
        if len(buf) >= 4:
            if any(buf.startswith(m) for m in _METHODS):
                st.proto = "h1"
                data = bytes(buf)
                buf.clear()
                self._make_splitter(st)
                self._ensure_conn_row(st)
                st.splitter.feed_request(data)
                return True
            # unknown protocol on this TLS conn (e.g. non-HTTP)
            st.proto = "other"
            self.log(f"conn {st.conn_id}: non-HTTP TLS stream, skipping")
            buf.clear()
            return True
        return False

    def _make_splitter(self, st: ConnectionState) -> None:
        cls = H2Splitter if st.proto == "h2" else H1Splitter
        st.splitter = cls(
            self.store,
            session=self.opts.session_name,
            conn_id=st.conn_id,
            host=st.host or "unknown",
            port=st.port,
            scheme="https",
            server_addr=st.peer,
        )

        def _done(tx_id: str) -> None:
            st.transactions += 1
            if self.on_tx:
                try:
                    self.on_tx(tx_id)
                except Exception:  # noqa: BLE001
                    pass

        st.splitter.on_tx_complete = _done

    def _feed_up(self, st: ConnectionState, data: bytes) -> None:
        if st.proto is None:
            st.first_buf.extend(data)
            self._detect_proto(st)
            return
        if st.proto == "other" or st.splitter is None:
            return
        st.splitter.feed_request(data)

    def _feed_down(self, st: ConnectionState, data: bytes) -> None:
        if st.proto is None:
            # hold downstream until protocol known from upstream
            st.down_buf.extend(data)
            if len(st.down_buf) > 1 << 20:
                st.down_buf.clear()
            return
        if st.proto == "other" or st.splitter is None:
            return
        if st.down_buf:
            pending = bytes(st.down_buf)
            st.down_buf.clear()
            st.splitter.feed_response(pending)
        st.splitter.feed_response(data)

    # ---- reporting ---------------------------------------------------------
    def live_summary(self) -> str:
        lines = []
        with self._lock:
            total_tx = sum(s.transactions for s in self._conns.values())
            lines.append(
                f"connections={len(self._conns)} transactions={total_tx} "
                f"hosts={len(self.host_stats)}"
            )
            by_host: dict[str, int] = {}
            for st in self._conns.values():
                h = st.host or "unknown"
                by_host[h] = by_host.get(h, 0) + st.transactions
            for h, n in sorted(by_host.items(), key=lambda kv: -kv[1])[:12]:
                lines.append(f"  {h:<48} {n} tx")
        if self.agent_stats:
            s = self.agent_stats
            lines.append(
                f"agent: write={s.get('write')} read={s.get('read')} "
                f"up={s.get('bytes_up')} down={s.get('bytes_down')} dropped={s.get('drops')}"
            )
        return "\n".join(lines)


def _norm_host(h: str) -> str:
    return h.split(":")[0].strip().lower() if h else h
