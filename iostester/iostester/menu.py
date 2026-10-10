"""Interactive CLI Menu for iOSTester.

Simplified, English-only menu interface for iOS Network & API Security Testing.
Includes live application inspection and dynamic Frida SSL Pinning Bypass.
"""
from __future__ import annotations

import os
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from . import BANNER, LEGAL_NOTICE, __version__
from .analyzer.engine import Engine, load_ruleset
from .analyzer.model import load_findings, save_findings, severity_summary
from .core.session import Session, sessions_root
from .device.manager import DeviceManager
from .interceptor.capture import TrafficStore
from .interceptor.frida_capture import CaptureOptions, FridaCapture
from .profile_gen.mobileconfig import (
    ProfileOptions,
    ProxyConfig,
    build_mobileconfig,
    generate_ca,
    load_ca,
    primary_ip,
)
from .report.generator import ReportGenerator

console = Console()


def _get_active_session_name(default: Optional[str] = None) -> Optional[str]:
    """Helper to select an existing session or prompt to create one."""
    sessions = Session.list_all()
    if not sessions:
        console.print("[yellow]No testing session found. Creating a default session 'live_audit'...[/yellow]")
        s = Session.create("live_audit")
        s.set_authorization(authorized_by="Security Tester", note="Automated session")
        try:
            dm = DeviceManager()
            info = dm.device_info()
            s.set_device(udid=info.udid, model=info.product_type or info.model, ios=info.ios_version)
        except Exception:
            pass
        return "live_audit"

    names = [s.get("name", "") for s in sessions if s.get("name")]
    if not names:
        return "live_audit"

    console.print("\n[bold cyan]Available Sessions:[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("Session Name", style="bold")
    table.add_column("Target App")
    table.add_column("Created")

    for idx, s in enumerate(sessions, 1):
        target = s.get("target", {}).get("bundle_id") or "-"
        table.add_row(str(idx), s.get("name", "?"), target, s.get("created", "-"))
    console.print(table)

    def_name = default if (default and default in names) else names[0]
    choice = Prompt.ask("Select session (number or name)", default=def_name).strip()
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        return names[int(choice) - 1]
    if choice in names:
        return choice
    return def_name


def _fetch_installed_apps() -> List[Dict[str, Any]]:
    """Retrieve all installed apps on connected device via Frida with running status."""
    apps_list: List[Dict[str, Any]] = []
    try:
        import frida
        dev = frida.get_usb_device()
        frida_apps = dev.enumerate_applications()
        for a in frida_apps:
            apps_list.append({
                "name": a.name,
                "identifier": a.identifier,
                "pid": a.pid or 0,
                "is_running": bool(a.pid),
            })
    except Exception:
        # Fallback to DeviceManager
        try:
            dm = DeviceManager()
            dm_apps = dm.list_apps(app_type="User")
            for bid, meta in dm_apps.items():
                name = meta.get("CFBundleDisplayName") or meta.get("CFBundleName") or bid
                apps_list.append({
                    "name": name,
                    "identifier": bid,
                    "pid": 0,
                    "is_running": False,
                })
        except Exception:
            pass

    # Sort: running apps first, then alphabetical
    apps_list.sort(key=lambda x: (0 if x["is_running"] else 1, x["name"].lower()))
    return apps_list


def menu_inspect_device() -> None:
    """Option 1: Inspect connected iOS device."""
    console.rule("[bold cyan]Connected iOS Device[/bold cyan]")
    try:
        dm = DeviceManager()
        devs = dm.list_devices()
    except Exception as e:
        console.print(f"[bold red]Failed to communicate with usbmuxd: {e}[/bold red]")
        return

    if not devs:
        console.print("[bold red]✗ No iOS device detected via USB.[/bold red]")
        console.print("[dim]Make sure your iPhone is connected, unlocked, and 'Trust This Computer' is accepted.[/dim]\n")
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


def menu_list_and_bypass_ssl() -> None:
    """Option 3: List all iPhone applications and run live Frida SSL Pinning Bypass."""
    console.rule("[bold cyan]iOS Applications & Live SSL Pinning Bypass (Frida)[/bold cyan]")

    with console.status("[bold cyan]Fetching installed applications from connected iPhone...[/bold cyan]"):
        apps = _fetch_installed_apps()

    if not apps:
        console.print("[bold red]✗ Could not retrieve applications. Make sure iPhone is connected and unlocked.[/bold red]")
        return

    running_count = sum(1 for a in apps if a["is_running"])
    console.print(f"\n[green]Found {len(apps)} total applications on iPhone[/green] ([bold cyan]{running_count} currently running[/bold cyan]):\n")

    table = Table(header_style="bold magenta", show_lines=False)
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Application Name", style="bold")
    table.add_column("Bundle Identifier", style="cyan")
    table.add_column("Status", justify="center")

    for idx, app in enumerate(apps, 1):
        if app["is_running"]:
            status_str = f"[bold green]RUNNING (PID {app['pid']})[/bold green]"
        else:
            status_str = "[dim]Stopped[/dim]"
        table.add_row(str(idx), app["name"], app["identifier"], status_str)

    console.print(table)

    console.print("\n[bold]Select Application to Bypass SSL Pinning:[/bold]")
    console.print("  • Enter the [bold cyan]number #[/bold cyan] from the table above")
    console.print("  • Or type the [bold cyan]Bundle ID[/bold cyan] or [bold cyan]PID[/bold cyan] directly")
    console.print("  • Or press [dim]Enter[/dim] / type '0' to cancel")

    # Suggest running app if available (prefer third party like MyTsel)
    def_choice = ""
    for idx, a in enumerate(apps, 1):
        if a["is_running"] and "mytsel" in a["name"].lower():
            def_choice = str(idx)
            break
    if not def_choice and running_count > 0:
        for idx, a in enumerate(apps, 1):
            if a["is_running"] and not a["identifier"].startswith("com.apple."):
                def_choice = str(idx)
                break

    choice = Prompt.ask("\nTarget application", default=def_choice or "1").strip()
    if not choice or choice == "0":
        console.print("[yellow]Cancelled.[/yellow]")
        return

    selected_app = None
    if choice.isdigit() and 1 <= int(choice) <= len(apps):
        selected_app = apps[int(choice) - 1]
    else:
        # Search by identifier or name
        for a in apps:
            if choice.lower() == a["identifier"].lower() or choice.lower() == a["name"].lower():
                selected_app = a
                break

    if not selected_app:
        console.print(f"[red]Application '{choice}' not found.[/red]")
        return

    app_name = selected_app["name"]
    bundle_id = selected_app["identifier"]
    pid = selected_app["pid"]

    console.print(f"\n[bold green]Target Selected:[/bold green] [bold cyan]{app_name}[/bold cyan] ({bundle_id})")

    # Load embedded bypass script
    from .agent.ssl_bypass import SSL_BYPASS_SCRIPT
    script_code = SSL_BYPASS_SCRIPT

    import frida
    device = frida.get_usb_device()
    session = None

    try:
        # Strategy: Try attach first. If it fails with (os/kern) failure or anti-attach protection,
        # automatically fallback to spawning the app fresh with Frida hooks injected before main().
        attached = False
        if pid and pid > 0:
            console.print(f"[*] Attaching to running process [bold cyan]{app_name}[/bold cyan] (PID {pid})...")
            try:
                session = device.attach(pid)
                attached = True
            except Exception as attach_err:
                console.print(f"[yellow]! Attach prevented by iOS/App ({attach_err}).[/yellow]")
                console.print(f"[*] Switching to clean spawn mode for [bold cyan]{bundle_id}[/bold cyan]...")

        if not attached:
            try:
                # Kill stale instance if it was running
                if pid and pid > 0:
                    try:
                        device.kill(pid)
                        time.sleep(0.5)
                    except Exception:
                        pass
                new_pid = device.spawn([bundle_id])
                session = device.attach(new_pid)
                script = session.create_script(script_code)
                script.on("message", lambda m, d: None)
                script.load()
                device.resume(new_pid)
                console.print(f"[green]✓ App spawned fresh (PID {new_pid}) with bypass injected at startup![/green]")
            except Exception as spawn_err:
                console.print(f"[bold red]✗ Failed to launch app: {spawn_err}[/bold red]")
                return
        else:
            script = session.create_script(script_code)
            script.on("message", lambda m, d: None)
            script.load()

        console.print()
        console.print(Panel.fit(
            f"[bold green]✔ SSL PINNING BYPASS IS ACTIVE ON IPHONE![/bold green]\n\n"
            f"  • Target: [bold white]{app_name}[/bold white] ([cyan]{bundle_id}[/cyan])\n"
            f"  • Status: [bold green]Injected & Intercepting TLS Validations[/bold green]\n\n"
            f"All HTTPS/TLS requests from [bold]{app_name}[/bold] are now accepted without validation\n"
            f"and will forward cleanly into your [bold cyan]Burp Suite[/bold cyan] HTTP history!\n\n"
            f"[yellow]Perform your testing actions inside the app on your iPhone now.[/yellow]\n"
            f"[dim]Press Ctrl+C to stop bypass and detach.[/dim]",
            title="Live Bypass Session",
            border_style="green",
        ))

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping bypass...[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Bypass error: {e}[/bold red]")
    finally:
        if session:
            try:
                session.detach()
            except Exception:
                pass
        console.print("[bold green]✓ Detached cleanly from iPhone process.[/bold green]")


def menu_setup_burp_proxy() -> None:
    """Option 2: Setup Burp Suite / Mitmproxy CA certificate and Wi-Fi proxy instructions."""
    console.rule("[bold cyan]Setup Proxy & Install Root CA Certificate[/bold cyan]")
    session_name = _get_active_session_name()
    if not session_name:
        return

    s = Session.load(session_name)
    ca_dir = s.profile_dir / "ca"
    if not (ca_dir / "ca.crt.pem").exists():
        console.print("[cyan]Generating new Root CA certificate for this session...[/cyan]")
        ca = generate_ca(ca_dir, common_name=f"iOSTester CA ({session_name})")
    else:
        ca = load_ca(ca_dir)

    detected_ip = primary_ip()
    console.print("\n[bold]Proxy Settings (Burp Suite / Mitmproxy):[/bold]")
    proxy_host = Prompt.ask("Computer LAN IP (Proxy Host)", default=detected_ip).strip()
    proxy_port = IntPrompt.ask("Proxy Port (Burp default: 8080)", default=8080)

    opts = ProfileOptions(
        display_name=f"iOSTester CA ({session_name})",
        proxy=ProxyConfig(host=proxy_host, port=proxy_port),
        include_global_proxy=False,  # CA-only profile to ensure compatibility with non-supervised iPhones
    )
    profile_path = s.profile_dir / f"{session_name}.mobileconfig"
    build_mobileconfig(ca, opts, profile_path)

    console.print(f"\n[bold green]✓ Root CA Profile Ready:[/bold green] {profile_path}")
    console.print(f"  • CA SHA-256 Fingerprint: [cyan]{ca.ca_fingerprint_sha256}[/cyan]")
    console.print(f"  • Target Proxy: [bold cyan]{proxy_host}:{proxy_port}[/bold cyan]")

    console.print("\n[bold]Install CA Certificate to iPhone:[/bold]")
    console.print("  [1] Open Web Server & QR Code (Download via Safari - Recommended)")
    console.print("  [2] Push directly via USB")
    console.print("  [3] Skip certificate installation")
    install_choice = Prompt.ask("Select option", choices=["1", "2", "3"], default="1")

    if install_choice == "1":
        serve_port = IntPrompt.ask("Local HTTP Server Port", default=8000)
        from .cli import _serve_profile
        _serve_profile(profile_path, proxy_host, serve_port)
    elif install_choice == "2":
        try:
            dm = DeviceManager()
            dm.install_profile(profile_path)
            console.print("[bold green]✓ Profile pushed to iPhone![/bold green]")
            console.print("  1. Go to [bold]Settings > General > VPN & Device Management > Install[/bold]")
            console.print("  2. Go to [bold]Settings > General > About > Certificate Trust Settings[/bold],")
            console.print("     toggle [bold green]Full Trust for Root Certificates[/bold green] ON.")
        except Exception as e:
            console.print(f"[bold red]Failed to push via USB ({e}). Use option [1] instead.[/bold red]")

    console.print(Panel.fit(
        f"[bold cyan]Burp Suite Setup Checklist:[/bold cyan]\n\n"
        f"1. In [bold]Burp Suite[/bold]:\n"
        f"   Go to [bold]Proxy > Proxy settings > Proxy listeners[/bold]\n"
        f"   Edit listener -> Bind to [bold cyan]All interfaces[/bold cyan] on port [bold cyan]{proxy_port}[/bold cyan].\n\n"
        f"2. On your [bold]iPhone[/bold]:\n"
        f"   Go to [bold]Settings > Wi-Fi[/bold] -> tap [bold](i)[/bold] icon on your active Wi-Fi.\n"
        f"   Scroll down -> [bold]Configure Proxy > Manual[/bold].\n"
        f"   Server: [bold green]{proxy_host}[/bold green] | Port: [bold green]{proxy_port}[/bold green] -> tap [bold]Save[/bold].\n\n"
        f"3. In [bold]Burp Suite[/bold]:\n"
        f"   Open [bold]Proxy > HTTP history[/bold] to see live HTTP/HTTPS traffic from iPhone.\n\n"
        f"4. If app traffic is blocked by SSL Pinning:\n"
        f"   Run [bold cyan]Option [3] (Bypass SSL Pinning)[/bold cyan] from the Main Menu.",
        title="Burp Suite Connection Guide",
        border_style="yellow"
    ))


def menu_intercept_traffic() -> None:
    """Option 4: In-process BoringSSL TLS Capture & Storage."""
    console.rule("[bold cyan]Capture & Save Plaintext TLS Traffic into Session DB[/bold cyan]")
    session_name = _get_active_session_name()
    if not session_name:
        return

    s = Session.load(session_name)
    def_app = s.meta.get("target", {}).get("bundle_id") or ""

    apps = _fetch_installed_apps()
    running_apps = [a for a in apps if a["is_running"]]

    if not def_app and running_apps:
        console.print("\n[dim]Running Apps Detected:[/dim]")
        for i, a in enumerate(running_apps[:10], 1):
            console.print(f"  [cyan]{i}[/cyan]. {a['name']} ([dim]{a['identifier']}[/dim])")
        app_choice = Prompt.ask("Enter Target Bundle ID (or pick number)", default="1").strip()
        if app_choice.isdigit() and 1 <= int(app_choice) <= len(running_apps):
            app_target = running_apps[int(app_choice) - 1]["identifier"]
        else:
            app_target = app_choice
    else:
        app_target = Prompt.ask("Target App Bundle ID", default=def_app or "telkomsel.mytelkomsel-dev").strip()

    if not app_target:
        console.print("[red]Bundle ID is required![/red]")
        return

    s.set_target(bundle_id=app_target)

    duration_str = Prompt.ask("Capture duration in seconds (leave empty to capture until Ctrl+C)", default="30").strip()
    duration: Optional[float] = float(duration_str) if duration_str else None

    store = TrafficStore(s.db_path)
    opts = CaptureOptions(
        session_name=session_name,
        bundle_id=app_target,
    )

    console.print(f"\n[bold green]Starting In-Process Interceptor on '{session_name}'...[/bold green]")
    console.print(f"  Target: [bold cyan]{app_target}[/bold cyan]")
    console.print("  [dim]Open and use the app on your iPhone. Press Ctrl+C anytime to stop capture.[/dim]\n")

    tx_count = [0]
    def on_tx(tx_id: str):
        tx_count[0] += 1
        tx = store.get(tx_id, decode=False)
        if tx:
            st = tx.get("status") or "-"
            method = tx.get("method") or "?"
            host = tx.get("host") or "?"
            path = (tx.get("path") or "/")[:45]
            console.print(f"  [green][{st}][/green] [bold]{method:<5}[/bold] {host}{path} [dim]({tx_id})[/dim]")

    cap = FridaCapture(
        store=store,
        opts=opts,
        on_tx=on_tx,
        log=lambda m: console.print(f"[dim]{m}[/dim]"),
    )

    try:
        cap.start()
        s.log_event("intercept_start", target=app_target)
        cap.run_forever(duration=duration)
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture stopped by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Interception error: {e}[/bold red]")
    finally:
        cap.stop()
        store.close()
        s.log_event("intercept_stop", total_tx=tx_count[0])

    console.print(f"\n[bold green]✓ Done![/bold green] Total {tx_count[0]} transactions stored in: {s.db_path}")


def menu_scan_owasp() -> None:
    """Option 5: Scan captured traffic against OWASP API Top 10."""
    console.rule("[bold cyan]Scan Captured Traffic (OWASP API Security Top 10)[/bold cyan]")
    session_name = _get_active_session_name()
    if not session_name:
        return

    s = Session.load(session_name)
    if not s.db_path.exists():
        console.print("[yellow]No traffic database found for this session.[/yellow]")
        console.print("[dim]Please capture traffic first using Option [4].[/dim]\n")
        return

    store = TrafficStore(s.db_path)
    stats = store.stats()

    if stats["transactions"] == 0:
        console.print("[yellow]0 transactions captured in this session.[/yellow]")
        console.print("[dim]Please capture live traffic first using Option [4].[/dim]\n")
        store.close()
        return

    console.print(f"Session [bold cyan]{session_name}[/bold cyan]: {stats['transactions']} transactions across {stats['hosts']} hosts.")

    console.print("\n[bold]Select Scan Mode:[/bold]")
    console.print("  [1] Passive Scan (Header analysis, token leaks, information disclosure)")
    console.print("  [2] Active Scan  (Replay requests with BOLA, rate-limit & mass-assignment mutations)")
    mode_choice = Prompt.ask("Mode", choices=["1", "2"], default="1")
    is_active = (mode_choice == "2")

    allow_hosts = []
    if is_active:
        host_str = Prompt.ask("Restrict active replay to specific host(s) (comma-separated, or empty for all)", default="").strip()
        if host_str:
            allow_hosts = [h.strip() for h in host_str.split(",") if h.strip()]

    rules = load_ruleset("owasp-api-top10")
    engine = Engine(
        store=store,
        session_name=session_name,
        log=lambda m: console.print(f"[dim]{m}[/dim]"),
    )

    with console.status("[bold cyan]Analyzing traffic against OWASP API Top 10 rules...[/bold cyan]"):
        try:
            findings = engine.run_all(
                ruleset=rules,
                active=is_active,
                allow_hosts=allow_hosts if allow_hosts else None,
            )
        except Exception as e:
            console.print(f"[bold red]Scan error: {e}[/bold red]")
            store.close()
            return

    save_findings(findings, s.findings_path)
    store.close()

    sev = severity_summary(findings)
    console.print("\n[bold]Vulnerability Findings Summary:[/bold]")
    table = Table(header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for level in ("critical", "high", "medium", "low", "info"):
        cnt = sev.get(level, 0)
        color = "red" if level in ("critical", "high") else ("yellow" if level == "medium" else "blue")
        table.add_row(f"[{color}]{level.upper()}[/{color}]", str(cnt))
    console.print(table)
    console.print(f"\n[bold green]✓ {len(findings)} findings saved to:[/bold green] {s.findings_path}")


def menu_generate_report() -> None:
    """Option 6: Generate assessment reports (HTML, PDF, JSON)."""
    console.rule("[bold cyan]Generate Security Assessment Reports[/bold cyan]")
    session_name = _get_active_session_name()
    if not session_name:
        return

    s = Session.load(session_name)
    if not s.findings_path.exists():
        console.print("[red]No findings found. Run OWASP scan (Option [5]) first.[/red]")
        return

    findings = load_findings(s.findings_path)
    store = TrafficStore(s.db_path) if s.db_path.exists() else None
    rep = ReportGenerator(s, findings)

    fmt_choice = Prompt.ask("Report format(s)", choices=["html,pdf", "html", "pdf", "html,pdf,json"], default="html,pdf")
    formats = [f.strip().lower() for f in fmt_choice.split(",")]

    with console.status("[bold cyan]Compiling assessment report...[/bold cyan]"):
        try:
            outputs = rep.write_all(formats, store=store)
            if "json" in formats:
                j_path = s.report_dir / "report.json"
                rep.export_json(j_path)
                outputs["json"] = j_path
        except Exception as e:
            console.print(f"[bold red]Report generation failed: {e}[/bold red]")
            return

    console.print("\n[bold green]✓ Reports successfully created:[/bold green]")
    for f_type, path in outputs.items():
        console.print(f"  • {f_type.upper()}: [underline]{path}[/underline]")

    if "html" in outputs and Confirm.ask("\nOpen HTML report in browser now?", default=True):
        try:
            webbrowser.open(outputs["html"].resolve().as_uri())
        except Exception:
            pass


def interactive_menu() -> None:
    """Main clean, simplified interactive menu loop."""
    while True:
        try:
            console.clear()
        except Exception:
            pass

        console.print(f"[bold cyan]{BANNER.strip()}[/bold cyan]")
        console.print(f"[yellow]{LEGAL_NOTICE}[/yellow]\n")

        # Quick device connection status
        try:
            dm = DeviceManager()
            devs = dm.list_devices()
            if devs:
                dev = devs[0]
                console.print(f"[bold green]● Connected Device:[/bold green] {dev.name} ({dev.product_type}, iOS {dev.ios_version})\n")
            else:
                console.print("[dim]○ No iOS device connected via USB.[/dim]\n")
        except Exception:
            pass

        console.print(Panel.fit(
            "[bold white]MAIN MENU:[/bold white]\n\n"
            "  [bold cyan][1][/bold cyan] 📱  [bold]Check Connected Device Info[/bold]\n"
            "  [bold cyan][2][/bold cyan] 🌐  [bold]Setup Proxy & Install Root CA (Burp Suite)[/bold]\n"
            "  [bold cyan][3][/bold cyan] ⚡  [bold green]Bypass SSL Pinning on iPhone App (Frida Live)[/bold green]\n"
            "  [bold cyan][4][/bold cyan] 🎯  [bold]Capture & Save Plaintext TLS Traffic[/bold]\n"
            "  [bold cyan][5][/bold cyan] 🔍  [bold]Scan Vulnerabilities (OWASP API Top 10)[/bold]\n"
            "  [bold cyan][6][/bold cyan] 📄  [bold]Generate Reports (HTML & PDF)[/bold]\n"
            "  [bold red][0][/bold red] 🚪  [bold red]Exit[/bold red]",
            title="iOSTester Control Center",
            border_style="cyan",
        ))

        try:
            choice = Prompt.ask("\nSelect option", choices=["1", "2", "3", "4", "5", "6", "0"], default="3")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[cyan]Goodbye![/cyan]")
            break

        try:
            if choice == "1":
                menu_inspect_device()
            elif choice == "2":
                menu_setup_burp_proxy()
            elif choice == "3":
                menu_list_and_bypass_ssl()
            elif choice == "4":
                menu_intercept_traffic()
            elif choice == "5":
                menu_scan_owasp()
            elif choice == "6":
                menu_generate_report()
            elif choice == "0":
                console.print("[cyan]Thank you for using iOSTester. Goodbye![/cyan]")
                break
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled.[/yellow]")
        except Exception as err:
            console.print(f"\n[bold red]Error: {err}[/bold red]")

        try:
            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]", default="")
        except (KeyboardInterrupt, EOFError):
            break
