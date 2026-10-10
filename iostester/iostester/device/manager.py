"""Device communication via pymobiledevice3 (libimobiledevice-compatible).

All calls degrade gracefully: if pymobiledevice3 is not installed we fall
back to libimobiledevice CLI tools (idevice_id / ideviceinstaller) when
available, then to a clear error.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class DeviceInfo:
    udid: str
    name: str = "iPhone"
    model: str | None = None
    product_type: str | None = None
    ios_version: str | None = None
    connection: str | None = None

    def describe(self) -> str:
        bits = [f"{self.name} ({self.product_type or self.model or '?'}"]
        if self.ios_version:
            bits.append(f"iOS {self.ios_version}")
        if self.connection:
            bits.append(self.connection)
        return ", ".join(bits) + f") udid={self.udid[:12]}..."


class DeviceManager:
    def __init__(self, udid: str | None = None, timeout: int = 60):
        self.udid = udid
        self.timeout = timeout
        self._pmd3 = shutil.which("pymobiledevice3") or _module_available("pymobiledevice3")

    # ------------------------------------------------------------------
    def _run(self, args: list[str], parse_json: bool = True) -> Any:
        if not self._pmd3:
            raise RuntimeError(
                "pymobiledevice3 is required for device operations. "
                "Install with: pip install pymobiledevice3"
            )
        cmd = [self._pmd3] + args
        if self.udid and "--udid" not in args:
            cmd += ["--udid", self.udid]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise RuntimeError(f"{' '.join(cmd[:3])} failed: {err[-1] if err else 'unknown error'}")
        out = proc.stdout.strip()
        if parse_json and out:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return out
        return out

    # ------------------------------------------------------------------
    def list_devices(self) -> list[DeviceInfo]:
        try:
            data = self._run(["usbmux", "list"])
        except Exception:  # noqa: BLE001
            return []
        out: list[DeviceInfo] = []
        for d in data if isinstance(data, list) else []:
            out.append(
                DeviceInfo(
                    udid=d.get("UniqueDeviceID") or d.get("Identifier", ""),
                    name=d.get("DeviceName", "iPhone"),
                    model=d.get("DeviceClass"),
                    product_type=d.get("ProductType"),
                    ios_version=d.get("ProductVersion"),
                    connection=d.get("ConnectionType"),
                )
            )
        return out

    def first_device(self) -> DeviceInfo | None:
        devs = self.list_devices()
        if not devs:
            return None
        if self.udid:
            for d in devs:
                if d.udid == self.udid:
                    return d
        return devs[0]

    def info(self) -> dict[str, Any]:
        return self._run(["lockdown", "info"])

    def device_info(self) -> DeviceInfo:
        info = self.info()
        d = self.first_device()
        udid = self.udid or (d.udid if d else info.get("UniqueDeviceID", ""))
        return DeviceInfo(
            udid=udid,
            name=info.get("DeviceName", d.name if d else "iPhone"),
            model=info.get("DeviceClass"),
            product_type=info.get("ProductType"),
            ios_version=info.get("ProductVersion"),
            connection=d.connection if d else None,
        )

    # ---- apps -----------------------------------------------------------
    def list_apps(self, app_type: str = "User", calculate_size: bool = False) -> dict[str, Any]:
        args = ["apps", "list", "--type", app_type]
        if calculate_size:
            args.append("--calculate-size")
        data = self._run(args)
        return data if isinstance(data, dict) else {}

    def find_app(self, bundle_id: str) -> dict[str, Any] | None:
        apps = self.list_apps("Any")
        return apps.get(bundle_id)

    def app_version(self, bundle_id: str) -> str | None:
        app = self.find_app(bundle_id)
        if not app:
            return None
        return app.get("CFBundleShortVersionString") or app.get("CFBundleVersion")

    def install(self, ipa_path: str | Path) -> str:
        return self._run(["apps", "install", str(ipa_path)], parse_json=False)

    def uninstall(self, bundle_id: str) -> str:
        return self._run(["apps", "uninstall", bundle_id], parse_json=False)

    # ---- profiles --------------------------------------------------------
    def list_profiles(self) -> dict[str, Any]:
        data = self._run(["profile", "list"])
        return data if isinstance(data, dict) else {"raw": data}

    def install_profile(self, path: str | Path) -> str:
        return self._run(["profile", "install", str(path)], parse_json=False)

    def remove_profile(self, name: str) -> str:
        return self._run(["profile", "remove", name], parse_json=False)

    # ---- pcap ------------------------------------------------------------
    def pcap(self, out: str | Path, count: int = -1, process: str | None = None) -> str:
        args = ["pcap", "--out", str(out), "-c", str(count)]
        if process:
            args += ["--process", process]
        return self._run(args, parse_json=False)


def _module_available(name: str) -> str | None:
    import importlib.util

    if importlib.util.find_spec(name):
        import sys

        exe = Path(sys.executable).parent / (name + ".exe")
        if exe.exists():
            return str(exe)
        exe2 = Path(sys.executable).parent / name
        if exe2.exists():
            return str(exe2)
        return name  # let subprocess resolve via PATH
    return None
