"""iosf-ng: Next-Generation iOS Security & API Testing Framework.

Recon-ng styled interactive console for iOS Mobile Security Assessments.
"""
from __future__ import annotations

import os
import sys
import time
import shlex
import webbrowser
from pathlib import Path
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm

from .device.manager import DeviceManager
from .core.session import Session
from .agent.ssl_bypass import SSL_BYPASS_SCRIPT
from .profile_gen.mobileconfig import (
    ProfileOptions,
    ProxyConfig,
    build_mobileconfig,
    generate_ca,
    load_ca,
    primary_ip,
)
from .interceptor.capture import TrafficStore
from .interceptor.frida_capture import CaptureOptions, FridaCapture
from .analyzer.engine import Engine, load_ruleset
from .analyzer.model import load_findings, save_findings, severity_summary
from .report.generator import ReportGenerator

console = Console()


class IOSFConsole:
    def __init__(self):
        self.active_session = "default"
        self.target_bundle = ""
        self.proxy_host = primary_ip()
        self.proxy_port = 8080
        self.device_info_str = "None"
        self._refresh_device()

    def _refresh_device(self):
        try:
            dm = DeviceManager()
            devs = dm.list_devices()
            if devs:
                d = devs[0]
                self.device_info_str = f"{d.name} ({d.product_type or d.model}, iOS {d.ios_version})"
            else:
                self.device_info_str = "No USB Device"
        except Exception:
            self.device_info_str = "No USB Device"

    def print_banner(self):
        banner_lines = [
            " ___ ___  ___  ___       _  _  ___ ",
            "|_ _/ _ \\/ __|| __|     | \\| |/ __|",
            " | | (_) \\__ \\| _|  --- | .` | (_ |",
            "|___\\___/|___/|_|       |_|\\_|\\___|"
        ]
        console.print()
        for line in banner_lines:
            console.print(Text(line, style="bold cyan"))
        console.print(Text("\nCreated By Anonre", style="bold yellow"))
        console.print(Text("iOS Mobile Security & API Testing Framework (Next-Gen)", style="bold white"))
        console.print(Text("Non-Jailbreak & Jailbroken iOS Support\n", style="dim"))

        cmd_table = Table(
            title="[bold yellow]QUICK COMMAND REFERENCE[/bold yellow]",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            expand=True
        )
        cmd_table.add_column("Command", style="bold green", width=20)
        cmd_table.add_column("Shortcut", style="bold cyan", width=10)
        cmd_table.add_column("Description", style="white")

        cmd_table.add_row("help", "?", "Display available commands and usage guide")
        cmd_table.add_row("devices", "dev", "Inspect connected physical iOS devices (USB)")
        cmd_table.add_row("apps", "ls", "List all installed applications with live running status")
        cmd_table.add_row("bypass <app/id>", "bp", "Live Frida SSL Pinning Bypass (Attach / Auto-Spawn)")
        cmd_table.add_row("proxy", "ca", "Setup Burp Suite Root CA profile & Wi-Fi proxy guide")
        cmd_table.add_row("intercept", "cap", "Capture in-process plaintext TLS traffic into SQLite DB")
        cmd_table.add_row("scan [passive|active]", "audit", "Scan traffic against OWASP Mobile & API Top 10")
        cmd_table.add_row("report [html|pdf]", "rep", "Generate security assessment reports")
        cmd_table.add_row("set <key> <val>", "set", "Set workspace variables (target, proxy_host, port, session)")
        cmd_table.add_row("show", "info", "Show current workspace variables and status")
        cmd_table.add_row("clear", "cls", "Clear terminal screen")
        cmd_table.add_row("exit", "quit", "Exit iosf-ng console")

        console.print(cmd_table)
        console.print(f"[bold dim]Status:[/bold dim] [bold green]Device:[/bold green] {self.device_info_str} | [bold green]Session:[/bold green] {self.active_session} | [bold green]Proxy:[/bold green] {self.proxy_host}:{self.proxy_port}\n")

    def cmd_help(self):
        console.rule("[bold cyan]iosf-ng Command Guide[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Command / Alias", style="bold green", width=26)
        table.add_column("Syntax Example", style="yellow", width=34)
        table.add_column("Description")

        table.add_row("devices, dev", "devices", "Check USB iOS device connection and UDID")
        table.add_row("apps, ls", "apps", "Enumerate installed apps, bundle IDs, and PIDs")
        table.add_row("bypass, bp", "bypass 6  OR  bypass MyTsel", "Launch live Frida SSL Pinning bypass")
        table.add_row("proxy, ca", "proxy", "Generate & serve Burp Suite .mobileconfig CA")
        table.add_row("intercept, cap", "intercept", "Record unencrypted HTTP/HTTPS API traffic")
        table.add_row("scan, audit", "scan active", "Run OWASP API Security Top 10 vulnerabilities")
        table.add_row("report, rep", "report html,pdf", "Compile HTML and PDF audit report")
        table.add_row("set", "set target telkomsel.mytelkomsel-dev", "Change active target, host, port, or session")
        table.add_row("show, info", "show", "View active configuration parameters")
        table.add_row("clear, cls", "clear", "Clear console screen")
        table.add_row("exit, quit, q", "exit", "Exit iosf-ng")
        console.print(table)

    def cmd_show(self):
        console.rule("[bold cyan]Current Workspace Configuration[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Variable", style="bold cyan")
        table.add_column("Value", style="bold green")
        table.add_column("Description")

        table.add_row("session", self.active_session, "Current assessment session directory name")
        table.add_row("target", self.target_bundle or "[dim]<not set>[/dim]", "Target application bundle identifier")
        table.add_row("proxy_host", self.proxy_host, "Burp Suite listener LAN IP address")
        table.add_row("proxy_port", str(self.proxy_port), "Burp Suite listener TCP port")
        table.add_row("device", self.device_info_str, "Connected iOS device status")
        console.print(table)

    def cmd_set(self, args: List[str]):
        if len(args) < 2:
            console.print("[yellow]Usage: set <variable> <value>[/yellow]")
            console.print("Variables: target, proxy_host, proxy_port, session")
            return
        var = args[0].lower()
        val = args[1]
        if var == "target":
            self.target_bundle = val
            console.print(f"[green]target =>[/green] {val}")
        elif var in ("proxy_host", "host"):
            self.proxy_host = val
            console.print(f"[green]proxy_host =>[/green] {val}")
        elif var in ("proxy_port", "port"):
            try:
                self.proxy_port = int(val)
                console.print(f"[green]proxy_port =>[/green] {val}")
            except ValueError:
                console.print("[red]Invalid port number.[/red]")
        elif var == "session":
            self.active_session = val
            console.print(f"[green]session =>[/green] {val}")
        else:
            console.print(f"[red]Unknown variable: {var}[/red]")

    def cmd_devices(self):
        console.rule("[bold cyan]Connected iOS Device[/bold cyan]")
        try:
            dm = DeviceManager()
            devs = dm.list_devices()
        except Exception as e:
            console.print(f"[bold red]Failed to communicate with usbmuxd: {e}[/bold red]")
            return

        if not devs:
            console.print("[bold red]✗ No iOS device detected via USB.[/bold red]")
            return

        table = Table(title="Detected iOS Device", header_style="bold green")
        table.add_column("Device Name", style="bold")
        table.add_column("Model")
        table.add_column("iOS Version")
        table.add_column("Connection")
        table.add_column("UDID", style="dim")
        for d in devs:
            table.add_row(
                d.name,
                f"{d.product_type or ''} ({d.model or ''})",
                d.ios_version or "-",
                d.connection or "-",
                d.udid,
            )
        console.print(table)
        self._refresh_device()

    def _fetch_apps(self) -> List[Dict[str, Any]]:
        apps_list = []
        try:
            import frida
            dev = frida.get_usb_device()
            for a in dev.enumerate_applications():
                apps_list.append({
                    "name": a.name,
                    "identifier": a.identifier,
                    "pid": a.pid or 0,
                    "is_running": bool(a.pid),
                })
        except Exception:
            try:
                dm = DeviceManager()
                for bid, meta in dm.list_apps(app_type="User").items():
                    name = meta.get("CFBundleDisplayName") or meta.get("CFBundleName") or bid
                    apps_list.append({
                        "name": name,
                        "identifier": bid,
                        "pid": 0,
                        "is_running": False,
                    })
            except Exception:
                pass
        apps_list.sort(key=lambda x: (0 if x["is_running"] else 1, x["name"].lower()))
        return apps_list

    def cmd_apps(self):
        console.rule("[bold cyan]Installed iOS Applications[/bold cyan]")
        with console.status("[bold cyan]Enumerating applications from connected iPhone...[/bold cyan]"):
            apps = self._fetch_apps()

        if not apps:
            console.print("[red]Could not retrieve applications. Ensure iPhone is unlocked.[/red]")
            return

        running_cnt = sum(1 for a in apps if a["is_running"])
        console.print(f"Total: [bold green]{len(apps)} apps[/bold green] ([bold cyan]{running_cnt} currently running[/bold cyan]):\n")

        table = Table(header_style="bold magenta")
        table.add_column("#", style="dim", justify="right", width=4)
        table.add_column("Application Name", style="bold")
        table.add_column("Bundle Identifier", style="cyan")
        table.add_column("Status", justify="center")

        for idx, app in enumerate(apps, 1):
            st = f"[bold green]RUNNING (PID {app['pid']})[/bold green]" if app["is_running"] else "[dim]Stopped[/dim]"
            table.add_row(str(idx), app["name"], app["identifier"], st)
        console.print(table)

    def cmd_bypass(self, target_arg: Optional[str] = None):
        console.rule("[bold cyan]Frida Live SSL Pinning Bypass[/bold cyan]")
        apps = self._fetch_apps()
        if not apps:
            console.print("[red]No device or applications available.[/red]")
            return

        selected_app = None
        if not target_arg:
            self.cmd_apps()
            choice = Prompt.ask("\nSelect application (# number, bundle ID, or name)").strip()
        else:
            choice = target_arg

        if choice.isdigit() and 1 <= int(choice) <= len(apps):
            selected_app = apps[int(choice) - 1]
        else:
            for a in apps:
                if choice.lower() in (a["identifier"].lower(), a["name"].lower()):
                    selected_app = a
                    break

        if not selected_app:
            console.print(f"[red]Application '{choice}' not found.[/red]")
            return

        app_name = selected_app["name"]
        bundle_id = selected_app["identifier"]
        pid = selected_app["pid"]
        self.target_bundle = bundle_id

        console.print(f"\n[green]Target:[/green] [bold cyan]{app_name}[/bold cyan] ({bundle_id})")

        import frida
        try:
            device = frida.get_usb_device()
        except Exception as e:
            console.print(f"[red]USB device error: {e}[/red]")
            return

        session = None
        try:
            attached = False
            if pid and pid > 0:
                console.print(f"[*] Attaching to PID [bold cyan]{pid}[/bold cyan]...")
                try:
                    session = device.attach(pid)
                    attached = True
                except Exception as e:
                    console.print(f"[yellow]! Attach blocked by iOS kernel ({e}). Switching to clean spawn mode...[/yellow]")

            if not attached:
                try:
                    if pid and pid > 0:
                        try:
                            device.kill(pid)
                            time.sleep(0.5)
                        except Exception:
                            pass
                    new_pid = device.spawn([bundle_id])
                    session = device.attach(new_pid)
                    script = session.create_script(SSL_BYPASS_SCRIPT)
                    script.on("message", lambda m, d: None)
                    script.load()
                    device.resume(new_pid)
                    console.print(f"[green]✓ Spawned fresh PID {new_pid} with bypass injected at startup![/green]")
                except Exception as spawn_err:
                    console.print(f"[red]Failed to launch app: {spawn_err}[/red]")
                    return
            else:
                script = session.create_script(SSL_BYPASS_SCRIPT)
                script.on("message", lambda m, d: None)
                script.load()

            console.print()
            console.print(Panel.fit(
                f"[bold green]✔ SSL PINNING BYPASS IS ACTIVE ON IPHONE![/bold green]\n\n"
                f"  • Target: [bold white]{app_name}[/bold white] ([cyan]{bundle_id}[/cyan])\n"
                f"  • Status: [bold green]Injected & Intercepting TLS Validations[/bold green]\n\n"
                f"All HTTPS requests from [bold]{app_name}[/bold] are now forwarded cleanly\n"
                f"to your [bold cyan]Burp Suite[/bold cyan] HTTP history ({self.proxy_host}:{self.proxy_port})!\n\n"
                f"[yellow]Perform your testing actions inside the app now.[/yellow]\n"
                f"[dim]Press Ctrl+C to stop bypass and return to console.[/dim]",
                title="Live Bypass Session",
                border_style="green",
            ))

            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping bypass session...[/yellow]")
        except Exception as e:
            console.print(f"[red]Bypass runtime error: {e}[/red]")
        finally:
            if session:
                try:
                    session.detach()
                except Exception:
                    pass
            console.print("[green]✓ Detached cleanly from iPhone.[/green]")

    def cmd_proxy(self):
        from .menu import menu_setup_burp_proxy
        menu_setup_burp_proxy()

    def cmd_intercept(self):
        from .menu import menu_intercept_traffic
        menu_intercept_traffic()

    def cmd_scan(self, mode_arg: Optional[str] = None):
        from .menu import menu_scan_owasp
        menu_scan_owasp()

    def cmd_report(self, fmt_arg: Optional[str] = None):
        from .menu import menu_generate_report
        menu_generate_report()

    def run(self):
        try:
            console.clear()
        except Exception:
            pass
        self.print_banner()

        while True:
            prompt_str = "[bold cyan]iosf-ng[/bold cyan] [bold green]$[/bold green] "

            try:
                raw_input = console.input(prompt_str).strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[cyan]Exiting iosf-ng. Goodbye![/cyan]")
                break

            if not raw_input:
                continue

            parts = shlex.split(raw_input)
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("exit", "quit", "q"):
                console.print("[cyan]Exiting iosf-ng. Goodbye![/cyan]")
                break
            elif cmd in ("help", "?"):
                self.cmd_help()
            elif cmd in ("clear", "cls"):
                try:
                    console.clear()
                except Exception:
                    pass
                self.print_banner()
            elif cmd in ("devices", "dev"):
                self.cmd_devices()
            elif cmd in ("apps", "ls"):
                self.cmd_apps()
            elif cmd in ("bypass", "bp"):
                self.cmd_bypass(args[0] if args else None)
            elif cmd in ("proxy", "ca"):
                self.cmd_proxy()
            elif cmd in ("intercept", "cap"):
                self.cmd_intercept()
            elif cmd in ("scan", "audit"):
                self.cmd_scan(args[0] if args else None)
            elif cmd in ("report", "rep"):
                self.cmd_report(args[0] if args else None)
            elif cmd == "set":
                self.cmd_set(args)
            elif cmd in ("show", "info"):
                self.cmd_show()
            else:
                console.print(f"[red]Unknown command: '{cmd}'. Type 'help' or '?' for available commands.[/red]")
