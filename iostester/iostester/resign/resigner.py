"""Phase 2: IPA unpacking, Frida Gadget injection, and resigning.

Pipeline
--------
1. Unzip the target IPA (standard ZIP archive containing `Payload/*.app`).
2. Copy `FridaGadget.dylib` into the `.app/Frameworks/` directory.
3. Inject a load command (`LC_LOAD_DYLIB`) into the main Mach-O executable
   so the dynamic linker (dyld) loads the gadget automatically on app start.
   Prefers `insert_dylib` or `optool` if installed, with a pure-Python Mach-O
   mutator fallback when native tools are absent.
4. Place `FridaGadget.config.json` next to the dylib configured in `script` or
   `listen` mode.
5. Re-sign all embedded frameworks + dylib + app bundle using `zsign` (Linux/
   Windows friendly, no macOS/Xcode required) or `codesign` (on macOS).
6. Repack into `.ipa` ready to deploy via `pymobiledevice3 apps install`.
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

GADGET_ASSET = Path(__file__).resolve().parent / "assets" / "FridaGadget.dylib"

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000
LC_RPATH = 0x1C | 0x80000000


@dataclass
class ResignOptions:
    ipa_path: Path
    out_ipa: Path
    p12_path: Optional[Path] = None
    p12_password: str = ""
    mobileprovision_path: Optional[Path] = None
    bundle_id: Optional[str] = None
    display_name: Optional[str] = None
    gadget_dylib: Optional[Path] = None
    gadget_mode: str = "listen"       # 'listen' or 'script'
    gadget_script: Optional[Path] = None
    gadget_port: int = 27042


class IPAResigner:
    def __init__(self, opts: ResignOptions, log: Optional[Callable[[str], None]] = None):
        self.opts = opts
        self.log = log or (lambda m: None)

    # ------------------------------------------------------------------
    # Step 1 & 6: unpack & repack
    # ------------------------------------------------------------------
    def unpack(self, work_dir: Path) -> Path:
        self.log(f"unpacking {self.opts.ipa_path.name}...")
        with zipfile.ZipFile(self.opts.ipa_path, "r") as zf:
            zf.extractall(work_dir)
        payload = work_dir / "Payload"
        if not payload.exists():
            raise FileNotFoundError("Invalid IPA: missing Payload directory")
        apps = [p for p in payload.iterdir() if p.suffix == ".app"]
        if not apps:
            raise FileNotFoundError("Invalid IPA: no .app found in Payload")
        return apps[0]

    def repack(self, work_dir: Path, out_path: Path) -> Path:
        self.log(f"repacking into {out_path.name}...")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            out_path.unlink()
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(work_dir):
                for f in files:
                    full = Path(root) / f
                    rel = full.relative_to(work_dir)
                    zf.write(full, rel)
        return out_path

    # ------------------------------------------------------------------
    # Step 2 & 4: Gadget placement & configuration
    # ------------------------------------------------------------------
    def place_gadget(self, app_dir: Path) -> Path:
        gadget_src = self.opts.gadget_dylib or GADGET_ASSET
        if not gadget_src.exists():
            # look in recon folder if asset not yet copied
            fallback = Path("E:/MOBILE/AIPOPX/_recon/gadget/FridaGadget.dylib")
            if fallback.exists():
                gadget_src = fallback
            else:
                raise FileNotFoundError(
                    f"FridaGadget.dylib not found at {gadget_src}. "
                    "Download it from https://github.com/frida/frida/releases or provide --gadget-path."
                )

        frameworks = app_dir / "Frameworks"
        frameworks.mkdir(exist_ok=True)
        gadget_dst = frameworks / "FridaGadget.dylib"
        self.log(f"copying Frida Gadget ({gadget_src.stat().st_size // 1024} KB) -> Frameworks/")
        shutil.copy2(gadget_src, gadget_dst)

        # Place FridaGadget.config.json
        cfg_path = frameworks / "FridaGadget.config.json"
        if self.opts.gadget_mode == "script" and self.opts.gadget_script:
            script_dst = frameworks / "agent.js"
            shutil.copy2(self.opts.gadget_script, script_dst)
            cfg = {
                "interaction": {
                    "type": "script",
                    "path": "agent.js",
                    "on_change": "rescan",
                }
            }
        else:
            cfg = {
                "interaction": {
                    "type": "listen",
                    "address": "0.0.0.0",
                    "port": self.opts.gadget_port,
                    "on_port_conflict": "pick-next",
                    "on_load": "wait",
                }
            }
        cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        self.log(f"wrote gadget config ({self.opts.gadget_mode} mode, port {self.opts.gadget_port})")
        return gadget_dst

    # ------------------------------------------------------------------
    # Step 3: LC_LOAD_DYLIB injection
    # ------------------------------------------------------------------
    def inject_load_command(self, app_dir: Path) -> None:
        info_plist = app_dir / "Info.plist"
        import plistlib
        with open(info_plist, "rb") as f:
            info = plistlib.load(f)
        exec_name = info.get("CFBundleExecutable")
        if not exec_name:
            raise ValueError("CFBundleExecutable not defined in Info.plist")
        binary_path = app_dir / exec_name
        dylib_install_path = "@executable_path/Frameworks/FridaGadget.dylib"

        self.log(f"injecting LC_LOAD_DYLIB into {exec_name}...")
        # Strategy A: insert_dylib CLI
        if shutil.which("insert_dylib"):
            cmd = ["insert_dylib", "--allyes", "--inplace", dylib_install_path, str(binary_path)]
            subprocess.run(cmd, check=True, capture_output=True)
            self.log("injected via insert_dylib")
            return

        # Strategy B: optool CLI
        if shutil.which("optool"):
            cmd = ["optool", "install", "-c", "load", "-p", dylib_install_path, "-t", str(binary_path)]
            subprocess.run(cmd, check=True, capture_output=True)
            self.log("injected via optool")
            return

        # Strategy C: Pure-Python Mach-O load command injector
        self._inject_macho_pure_python(binary_path, dylib_install_path)
        self.log("injected via pure-Python Mach-O injector")

    def _inject_macho_pure_python(self, binary_path: Path, dylib_path: str) -> None:
        """Inject LC_LOAD_DYLIB into a 64-bit Mach-O binary.

        Locates the header, checks for existing dylib reference, verifies
        there is space in the load command buffer, and appends a new
        dylib_command structure.
        """
        data = bytearray(binary_path.read_bytes())
        if len(data) < 32:
            raise ValueError("Binary too small to be a Mach-O")

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != MH_MAGIC_64:
            # Check FAT/Universal binary
            fat_magic = struct.unpack_from(">I", data, 0)[0]
            if fat_magic in (0xCAFEBABE, 0xBFBAFECA):
                self._inject_fat_macho(data, dylib_path)
                binary_path.write_bytes(data)
                return
            raise ValueError(f"Unsupported Mach-O magic: 0x{magic:08X} (expected MH_MAGIC_64)")

        self._inject_single_macho64(data, 0, dylib_path)
        binary_path.write_bytes(data)

    def _inject_single_macho64(self, data: bytearray, offset: int, dylib_path: str) -> None:
        # mach_header_64: magic(4), cputype(4), cpusubtype(4), filetype(4),
        #                 ncmds(4), sizeofcmds(4), flags(4), reserved(4) = 32 bytes
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            "<7I", data, offset
        )
        hdr_size = 32
        cmds_start = offset + hdr_size
        cmds_end = cmds_start + sizeofcmds

        # Format of dylib_command:
        #   uint32_t cmd; (LC_LOAD_DYLIB = 0x0c)
        #   uint32_t cmdsize;
        #   uint32_t name_offset; (always 24)
        #   uint32_t timestamp; (2)
        #   uint32_t current_version; (0)
        #   uint32_t compatibility_version; (0)
        #   char name[]; (padded to 8-byte boundary)
        dylib_bytes = dylib_path.encode("utf-8") + b"\x00"
        pad = (8 - (len(dylib_bytes) % 8)) % 8
        dylib_padded = dylib_bytes + (b"\x00" * pad)
        new_cmd_size = 24 + len(dylib_padded)

        # Check if already injected
        cur = cmds_start
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<2I", data, cur)
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
                name_off = struct.unpack_from("<I", data, cur + 8)[0]
                existing_name = data[cur + name_off: cur + cmdsize].split(b"\x00")[0].decode("utf-8", "ignore")
                if "FridaGadget" in existing_name:
                    self.log("FridaGadget load command already present, skipping injection")
                    return
            cur += cmdsize

        # Check if padding space exists before the first segment
        # In typical Mach-O, __PAGEZERO or __TEXT starts at offset 0 or page boundary,
        # and there is zero-padding after sizeofcmds up to the first section/segment offset.
        free_space = data[cmds_end: cmds_end + new_cmd_size]
        if any(b != 0 for b in free_space):
            raise RuntimeError(
                "Not enough zero-padding after load commands to inject new LC_LOAD_DYLIB. "
                "Use native `insert_dylib` or `optool`."
            )

        # Build new command
        new_cmd = struct.pack("<6I", LC_LOAD_DYLIB, new_cmd_size, 24, 2, 0, 0) + dylib_padded
        data[cmds_end: cmds_end + new_cmd_size] = new_cmd

        # Update header
        struct.pack_into("<2I", data, offset + 16, ncmds + 1, sizeofcmds + new_cmd_size)

    def _inject_fat_macho(self, data: bytearray, dylib_path: str) -> None:
        # FAT binary: parse architectures, inject into arm64 slices
        nfat = struct.unpack_from(">I", data, 4)[0]
        cur = 8
        injected = 0
        for _ in range(nfat):
            cputype, cpusubtype, offset, size, align = struct.unpack_from(">5I", data, cur)
            # CPU_TYPE_ARM64 = 0x0100000C
            if cputype == 0x0100000C:
                self._inject_single_macho64(data, offset, dylib_path)
                injected += 1
            cur += 20
        if injected == 0:
            raise RuntimeError("No arm64 slice found in FAT Mach-O binary")

    # ------------------------------------------------------------------
    # Step 5: Re-signing
    # ------------------------------------------------------------------
    def resign(self, app_dir: Path) -> None:
        self.log("signing application bundle...")
        zsign = shutil.which("zsign")
        codesign = shutil.which("codesign")

        if zsign and self.opts.p12_path:
            cmd = ["zsign", "-k", str(self.opts.p12_path)]
            if self.opts.p12_password:
                cmd += ["-p", self.opts.p12_password]
            if self.opts.mobileprovision_path:
                cmd += ["-m", str(self.opts.mobileprovision_path)]
            if self.opts.bundle_id:
                cmd += ["-b", self.opts.bundle_id]
            if self.opts.display_name:
                cmd += ["-n", self.opts.display_name]
            cmd.append(str(app_dir))
            self.log(f"running zsign: {' '.join(cmd[:4])}...")
            subprocess.run(cmd, check=True)
            return

        if codesign:
            self.log("using macOS codesign...")
            # Ad-hoc sign or use identity if available
            subprocess.run(
                ["codesign", "-f", "-s", "-", "--deep", str(app_dir)],
                check=True,
            )
            return

        self.log(
            "[WARN] Neither zsign nor codesign available. "
            "Bundle modified with Frida Gadget but NOT resigned. "
            "App will require AppSync (jailbroken) or manual resigning."
        )

    # ------------------------------------------------------------------
    # Full workflow
    # ------------------------------------------------------------------
    def process(self) -> Path:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="iostester_resign_") as tmp:
            work_dir = Path(tmp)
            app_dir = self.unpack(work_dir)
            self.place_gadget(app_dir)
            self.inject_load_command(app_dir)
            self.resign(app_dir)
            return self.repack(work_dir, self.opts.out_ipa)
