"""Session model: on-disk layout and metadata for a testing session."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import now_iso

DEFAULT_ROOT = "sessions"


def sessions_root() -> Path:
    import os

    root = os.environ.get("IOSTESTER_HOME")
    return Path(root) if root else Path.cwd() / DEFAULT_ROOT


@dataclass
class Session:
    name: str
    root: Path
    meta: dict[str, Any] = field(default_factory=dict)

    # ---- layout ---------------------------------------------------------
    @property
    def dir(self) -> Path:
        return self.root / self.name

    @property
    def db_path(self) -> Path:
        return self.dir / "traffic.sqlite"

    @property
    def meta_path(self) -> Path:
        return self.dir / "session.json"

    @property
    def profile_dir(self) -> Path:
        return self.dir / "profile"

    @property
    def logs_dir(self) -> Path:
        return self.dir / "logs"

    @property
    def report_dir(self) -> Path:
        return self.dir / "report"

    @property
    def exports_dir(self) -> Path:
        return self.dir / "exports"

    @property
    def findings_path(self) -> Path:
        return self.dir / "findings.json"

    @property
    def log_path(self) -> Path:
        return self.logs_dir / "session.jsonl"

    # ---- lifecycle ------------------------------------------------------
    @classmethod
    def create(cls, name: str, root: Path | None = None, **meta: Any) -> "Session":
        root = root or sessions_root()
        s = cls(name=name, root=root)
        s.dir.mkdir(parents=True, exist_ok=True)
        s.logs_dir.mkdir(exist_ok=True)
        s.profile_dir.mkdir(exist_ok=True)
        s.report_dir.mkdir(exist_ok=True)
        s.exports_dir.mkdir(exist_ok=True)
        s.meta = {
            "name": name,
            "created": now_iso(),
            "tool_version": getattr(__import__("iostester"), "__version__", "0.1.0"),
            "device": {},
            "target": {},
            "authorization": {},
        }
        s.meta.update(meta)
        s.save()
        s.log_event("session_created", name=name)
        return s

    @classmethod
    def load(cls, name: str, root: Path | None = None) -> "Session":
        root = root or sessions_root()
        s = cls(name=name, root=root)
        if not s.meta_path.exists():
            raise FileNotFoundError(
                f"Session '{name}' not found at {s.meta_path}. Run `iostester init --session {name}` first."
            )
        s.meta = json.loads(s.meta_path.read_text(encoding="utf-8"))
        return s

    @classmethod
    def list_all(cls, root: Path | None = None) -> list[dict[str, Any]]:
        root = root or sessions_root()
        out = []
        if root.exists():
            for d in sorted(root.iterdir()):
                meta = d / "session.json"
                if meta.exists():
                    try:
                        m = json.loads(meta.read_text(encoding="utf-8"))
                        out.append(m)
                    except Exception:  # noqa: BLE001
                        continue
        return out

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(json.dumps(self.meta, indent=2), encoding="utf-8")

    def log_event(self, kind: str, **kv: Any) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        entry = {"ts": now_iso(), "session": self.name, "event": kind, **kv}
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    # ---- convenience ----------------------------------------------------
    def set_target(self, bundle_id: str, app_version: str | None = None, name: str | None = None) -> None:
        self.meta.setdefault("target", {})
        self.meta["target"].update(
            {"bundle_id": bundle_id, "app_version": app_version, "app_name": name}
        )
        self.save()

    def set_device(self, udid: str, model: str | None = None, ios: str | None = None) -> None:
        self.meta.setdefault("device", {})
        self.meta["device"].update({"udid": udid, "model": model, "ios": ios})
        self.save()

    def set_authorization(self, authorized_by: str, note: str = "") -> None:
        self.meta["authorization"] = {
            "authorized_by": authorized_by,
            "note": note,
            "registered": now_iso(),
        }
        self.save()

    def summary(self) -> str:
        t = self.meta.get("target", {})
        d = self.meta.get("device", {})
        return (
            f"session={self.name} dir={self.dir} "
            f"target={t.get('bundle_id') or '-'} device={d.get('model') or '-'} ios={d.get('ios') or '-'}"
        )
