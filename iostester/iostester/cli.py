"""Command-line interface for iOSTester (Phase 6).

Full end-to-end workflow:
  1. iostester init       - initialize testing session, bind target app & device
  2. iostester profile    - generate .mobileconfig CA/proxy and serve or install
  3. iostester inject     - inject Frida Gadget into IPA & resign (non-jailbreak)
  4. iostester intercept  - live TLS plaintext capture from device app
  5. iostester scan       - run OWASP API Top 10 passive & active checks
  6. iostester report     - generate interactive HTML & PDF reports
  7. iostester devices    - inspect attached iOS devices
  8. iostester apps       - list installed apps on device
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from . import BANNER, LEGAL_NOTICE, __version__
from .core.session import Session, sessions_root
from .core.util import now_iso
from .device.manager import DeviceManager
from .profile_gen.mobileconfig import (
    CertificateBundle,
    ProfileOptions,
    ProxyConfig,
    build_mobileconfig,
    generate_ca,
    load_ca,
    primary_ip,
    sign_mobileconfig,
)
from .interceptor.capture import TrafficStore
from .interceptor.frida_capture import CaptureOptions, FridaCapture
from .analyzer.model import load_findings, save_findings, severity_summary
from .analyzer.engine import Engine, load_ruleset
from .report.generator import ReportGenerator
from .resign.resigner import IPAResigner, ResignOptions

console = Console()


def print_banner() -> None:
    console.print(f"[bold cyan]{BANNER.strip()}[/bold cyan]")
    console.print(f"[yellow]{LEGAL_NOTICE}[/yellow]\n")


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version=__version__, prog_name="iosf-ng")
def cli(ctx: click.Context) -> None:
    """iosf-ng: Next-Gen iOS Mobile Security & API Testing Framework."""
    if ctx.invoked_subcommand is None:
        from .console import IOSFConsole
        c = IOSFConsole()
        c.run()


@cli.command("console")
def cmd_console() -> None:
    """Launch the recon-ng styled iosf-ng interactive console."""
    from .console import IOSFConsole
    c = IOSFConsole()
    c.run()


@cli.command("menu")
def cmd_menu() -> None:
    """Launch the classic interactive menu wizard."""
    from .menu import interactive_menu
    interactive_menu()


# ---------------------------------------------------------------------------
# devices & apps inspection
# ---------------------------------------------------------------------------
@cli.command("devices")
def cmd_devices() -> None:
    """List connected iOS devices via usbmux."""
    dm = DeviceManager()
    devs = dm.list_devices()
    if not devs:
        console.print("[red]No connected iOS devices found.[/red]")
        return
    table = Table(title="Connected iOS Devices")
    table.add_column("Device Name", style="bold")
    table.add_column("Model / Class")
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


@cli.command("apps")
@click.option("--type", "app_type", default="User", help="Filter by System|User|Hidden|Any")
def cmd_apps(app_type: str) -> None:
    """List installed apps on the primary connected device."""
    dm = DeviceManager()
    apps = dm.list_apps(app_type=app_type)
    if not apps:
        console.print(f"[yellow]No {app_type} apps found or device not ready.[/yellow]")
        return
    table = Table(title=f"Installed Apps ({app_type})")
    table.add_column("Display Name", style="bold")
    table.add_column("Bundle Identifier", style="cyan")
    table.add_column("Version")
    for bundle_id, meta in sorted(apps.items()):
        name = meta.get("CFBundleDisplayName") or meta.get("CFBundleName") or "?"
        ver = meta.get("CFBundleShortVersionString") or meta.get("CFBundleVersion") or "-"
        table.add_row(str(name), bundle_id, str(ver))
    console.print(table)


# ---------------------------------------------------------------------------
# Phase 1: init & profile
# ---------------------------------------------------------------------------
@cli.command("init")
@click.option("--session", "name", required=True, help="Session name (alphanumeric/kebab)")
@click.option("--app", "app_path_or_bundle", help="Target IPA path or bundle identifier")
@click.option("--authorized-by", prompt="Authorized by (client/engagement contact)", help="Client/approver")
@click.option("--note", default="", help="Engagement scope note")
def cmd_init(name: str, app_path_or_bundle: Optional[str], authorized_by: str, note: str) -> None:
    """Initialize a new security testing session."""
    print_banner()
    s = Session.create(name)
    s.set_authorization(authorized_by=authorized_by, note=note)

    # Detect device
    try:
        dm = DeviceManager()
        info = dm.device_info()
        s.set_device(udid=info.udid, model=info.product_type or info.model, ios=info.ios_version)
        console.print(f"[green]✓ Connected device bound:[/green] {info.describe()}")
    except Exception as e:
        console.print(f"[yellow]! Device not auto-detected: {e}[/yellow]")

    # Target info
    if app_path_or_bundle:
        if app_path_or_bundle.endswith(".ipa") and Path(app_path_or_bundle).exists():
            s.set_target(bundle_id=Path(app_path_or_bundle).stem, name=Path(app_path_or_bundle).name)
        else:
            s.set_target(bundle_id=app_path_or_bundle)
        console.print(f"[green]✓ Target set:[/green] {app_path_or_bundle}")

    console.print(f"\n[bold green]Session '{name}' created at:[/bold green] {s.dir}")


@cli.command("profile")
@click.option("--session", "name", required=True, help="Session name")
@click.option("--proxy-host", help="Proxy IP address (defaults to primary local IP)")
@click.option("--proxy-port", default=8080, type=int, help="Proxy port (default 8080)")
@click.option("--install", is_flag=True, help="Auto-install to connected device via pymobiledevice3")
@click.option("--serve", is_flag=True, help="Start local web server with QR code for device download")
@click.option("--serve-port", default=8000, type=int, help="HTTP serve port")
def cmd_profile(name: str, proxy_host: Optional[str], proxy_port: int, install: bool, serve: bool, serve_port: int) -> None:
    """Generate .mobileconfig with Root CA and proxy settings (Phase 1)."""
    s = Session.load(name)
    ca_dir = s.profile_dir / "ca"
    if not (ca_dir / "ca.crt.pem").exists():
        console.print("[cyan]Generating new Root CA certificate...[/cyan]")
        ca = generate_ca(ca_dir, common_name=f"iOSTester CA ({name})")
    else:
        ca = load_ca(ca_dir)

    ip = proxy_host or primary_ip()
    opts = ProfileOptions(
        display_name=f"iOSTester CA ({name})",
        proxy=ProxyConfig(host=ip, port=proxy_port),
        include_global_proxy=False,
    )
    profile_path = s.profile_dir / f"{name}.mobileconfig"
    build_mobileconfig(ca, opts, profile_path)
    console.print(f"[green]✓ Profile generated:[/green] {profile_path}")
    console.print(f"  CA SHA-256: [cyan]{ca.ca_fingerprint_sha256}[/cyan]")
    console.print(f"  Proxy target: [bold]{ip}:{proxy_port}[/bold]")
    console.print("[dim]  (Profile contains testing Root CA compatible with standard non-supervised iPhones)[/dim]")

    if install:
        console.print("[cyan]Installing profile on device via pymobiledevice3...[/cyan]")
        try:
            dm = DeviceManager()
            dm.install_profile(profile_path)
            console.print("[green]✓ Profile pushed to device. Approve it in Settings > General > VPN & Device Management.[/green]")
        except Exception as e:
            console.print(f"[yellow]! Device push failed ({e}). Use --serve to install via Safari.[/yellow]")

    if serve:
        _serve_profile(profile_path, ip, serve_port)


def _serve_profile(profile_path: Path, ip: str, port: int) -> None:
    import http.server
    import socketserver
    import qrcode

    url = f"http://{ip}:{port}/{profile_path.name}"
    console.print(Panel.fit(
        f"[bold cyan]Install Root CA di iPhone via Safari:[/bold cyan]\n"
        f"[underline]{url}[/underline]\n\n"
        f"1. Buka URL di atas di Safari iPhone (atau scan QR code di bawah).\n"
        f"2. Izinkan unduh profil (Allow / Izinkan).\n"
        f"3. Buka [bold]Settings > Profile Downloaded > Install[/bold].\n"
        f"4. Buka [bold]Settings > General > About > Certificate Trust Settings[/bold],\n"
        f"   lalu aktifkan [bold green]Full Trust[/bold green] untuk iOSTester CA.",
        title="Server Profil & Root CA"
    ))

    # Print ASCII QR code in terminal
    qr = qrcode.QRCode(border=1)
    qr.add_data(url)
    qr.print_ascii(invert=True)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(profile_path.parent), **kwargs)
        def guess_type(self, path):
            if path.endswith(".mobileconfig"):
                return "application/x-apple-aspen-config"
            return super().guess_type(path)

    console.print(f"[dim]Serving {profile_path.name} on {url} (Ctrl+C to stop)...[/dim]")
    with socketserver.TCPServer(("", port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[dim]Server stopped.[/dim]")


# ---------------------------------------------------------------------------
# Phase 2: inject & resign
# ---------------------------------------------------------------------------
@cli.command("inject")
@click.option("--app", "ipa_path", required=True, type=click.Path(exists=True, path_type=Path), help="Path to target .ipa")
@click.option("--output", "out_ipa", required=True, type=click.Path(path_type=Path), help="Output resigned .ipa")
@click.option("--p12", "p12_path", type=click.Path(exists=True, path_type=Path), help="Signing certificate (.p12)")
@click.option("--password", "p12_password", default="", help="Password for .p12")
@click.option("--provision", "prov_path", type=click.Path(exists=True, path_type=Path), help="Mobileprovision profile")
@click.option("--bundle-id", help="Override CFBundleIdentifier")
@click.option("--mode", "gadget_mode", default="listen", type=click.Choice(["listen", "script"]), help="Gadget mode")
@click.option("--script", "gadget_script", type=click.Path(exists=True, path_type=Path), help="Script for script mode")
@click.option("--gadget-path", type=click.Path(exists=True, path_type=Path), help="Custom FridaGadget.dylib")
def cmd_inject(
    ipa_path: Path,
    out_ipa: Path,
    p12_path: Optional[Path],
    p12_password: str,
    prov_path: Optional[Path],
    bundle_id: Optional[str],
    gadget_mode: str,
    gadget_script: Optional[Path],
    gadget_path: Optional[Path],
) -> None:
    """Inject Frida Gadget into an IPA and resign it (Phase 2)."""
    print_banner()
    opts = ResignOptions(
        ipa_path=ipa_path,
        out_ipa=out_ipa,
        p12_path=p12_path,
        p12_password=p12_password,
        mobileprovision_path=prov_path,
        bundle_id=bundle_id,
        gadget_mode=gadget_mode,
        gadget_script=gadget_script,
        gadget_dylib=gadget_path,
    )
    resigner = IPAResigner(opts, log=lambda m: console.print(f"[dim]{m}[/dim]"))
    with console.status("[bold cyan]Injecting Frida Gadget and repacking...[/bold cyan]"):
        result = resigner.process()
    console.print(f"[bold green]✓ Injected IPA ready:[/bold green] {result} ({result.stat().st_size // (1024*1024)} MB)")
    console.print("[dim]Install to device with: pymobiledevice3 apps install <ipa>[/dim]")


# ---------------------------------------------------------------------------
# Phase 3: intercept
# ---------------------------------------------------------------------------
@cli.command("intercept")
@click.option("--session", "name", required=True, help="Session name")
@click.option("--app", "bundle_id", help="Target bundle id to spawn (e.g. telkomsel.mytelkomsel-dev)")
@click.option("--pid", type=int, help="Target process PID to attach")
@click.option("--filter-host", "hosts", multiple=True, help="Filter captured hosts (can be specified multiple times)")
@click.option("--duration", type=float, help="Capture duration in seconds (defaults to running until Ctrl+C)")
@click.option("--gadget-host", help="Attach to remote Frida Gadget, e.g. 127.0.0.1:27042")
def cmd_intercept(
    name: str,
    bundle_id: Optional[str],
    pid: Optional[int],
    hosts: tuple[str, ...],
    duration: Optional[float],
    gadget_host: Optional[str],
) -> None:
    """Capture live TLS plaintext traffic from target app (Phase 3)."""
    print_banner()
    s = Session.load(name)
    store = TrafficStore(s.db_path)

    # Determine bundle_id from session if not provided
    if not bundle_id and not pid and not gadget_host:
        bundle_id = s.meta.get("target", {}).get("bundle_id")
        if not bundle_id:
            raise click.UsageError("Provide --app <bundle_id> or --pid, or initialize target first via `init`.")

    opts = CaptureOptions(
        session_name=name,
        bundle_id=bundle_id,
        pid=pid,
        host_filter=list(hosts),
        gadget_host=gadget_host,
    )

    console.print(f"[bold cyan]Starting TLS Interceptor on session '{name}'...[/bold cyan]")
    if bundle_id:
        console.print(f"  Target: [bold]{bundle_id}[/bold]")
    if hosts:
        console.print(f"  Filter hosts: {', '.join(hosts)}")
    console.print("  [dim]Press Ctrl+C to stop interception and finalize transactions.[/dim]\n")

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
        s.log_event("intercept_start", target=bundle_id or pid or gadget_host)
        cap.run_forever(duration=duration)
    finally:
        cap.stop()
        store.close()
        s.log_event("intercept_stop", total_tx=tx_count[0])

    console.print(f"\n[bold green]Interception finished.[/bold green] Captured transactions stored in: {s.db_path}")


# ---------------------------------------------------------------------------
# Phase 4: scan (OWASP API Top 10)
# ---------------------------------------------------------------------------
@cli.command("scan")
@click.option("--session", "name", required=True, help="Session name")
@click.option("--ruleset", default="owasp-api-top10", help="Ruleset name or YAML path")
@click.option("--active", is_flag=True, help="Enable active replay tests (BOLA, rate limit, mass assignment)")
@click.option("--allow-host", "allow_hosts", multiple=True, help="Restrict active replays to specific hosts")
@click.option("--burst", default=10, type=int, help="Requests per burst for rate limit testing (default 10)")
@click.option("--delay", default=0.3, type=float, help="Delay between replay requests in seconds (default 0.3)")
def cmd_scan(name: str, ruleset: str, active: bool, allow_hosts: tuple[str, ...], burst: int, delay: float) -> None:
    """Run OWASP API Security Top 10 rule engine on captured traffic (Phase 4)."""
    print_banner()
    s = Session.load(name)
    store = TrafficStore(s.db_path)
    rules = load_ruleset(ruleset)

    stats = store.stats()
    console.print(f"Scanning session [bold]{name}[/bold]: {stats['transactions']} transactions across {stats['hosts']} hosts")
    if active:
        console.print("[yellow]Active replay mode enabled (replaying requests with mutations).[/yellow]")

    engine = Engine(
        store=store,
        session_name=name,
        log=lambda m: console.print(f"[dim]{m}[/dim]"),
    )

    with console.status("[bold cyan]Analyzing traffic against OWASP API Top 10...[/bold cyan]"):
        findings = engine.run_all(
            ruleset=rules,
            active=active,
            allow_hosts=list(allow_hosts) if allow_hosts else None,
            burst=burst,
            delay=delay,
        )

    save_findings(findings, s.findings_path)
    store.close()

    sev = severity_summary(findings)
    console.print("\n[bold]Scan Results Summary:[/bold]")
    table = Table()
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for level in ("critical", "high", "medium", "low", "info"):
        cnt = sev.get(level, 0)
        color = "red" if level in ("critical", "high") else ("yellow" if level == "medium" else "blue")
        table.add_row(f"[{color}]{level.upper()}[/{color}]", str(cnt))
    console.print(table)

    console.print(f"\n[green]✓ {len(findings)} findings saved to:[/green] {s.findings_path}")
    console.print("[dim]Generate report with: iostester report --session " + name + "[/dim]")


# ---------------------------------------------------------------------------
# Phase 5: report
# ---------------------------------------------------------------------------
@cli.command("report")
@click.option("--session", "name", required=True, help="Session name")
@click.option("--format", "fmt", default="html,pdf", help="Output format: html, pdf, json (default: html,pdf)")
def cmd_report(name: str, fmt: str) -> None:
    """Generate interactive HTML and formal PDF assessment reports (Phase 5)."""
    s = Session.load(name)
    if not s.findings_path.exists():
        console.print("[red]No findings found. Run `iostester scan` first.[/red]")
        sys.exit(1)

    findings = load_findings(s.findings_path)
    store = TrafficStore(s.db_path) if s.db_path.exists() else None
    rep = ReportGenerator(s, findings)
    formats = [f.strip().lower() for f in fmt.split(",")]

    console.print(f"Generating reports for session [bold]{name}[/bold] ({len(findings)} findings)...")
    outputs = rep.write_all(formats, store=store)

    for f_type, path in outputs.items():
        console.print(f"[bold green]✓ {f_type.upper()} report generated:[/bold green] {path}")

    if "json" in formats:
        j_path = s.report_dir / "report.json"
        rep.export_json(j_path)
        console.print(f"[bold green]✓ JSON export:[/bold green] {j_path}")


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------
@cli.command("sessions")
def cmd_sessions() -> None:
    """List all testing sessions."""
    sessions = Session.list_all()
    if not sessions:
        console.print("[dim]No sessions found in ./sessions[/dim]")
        return
    table = Table(title="iOSTester Sessions")
    table.add_column("Session Name", style="bold")
    table.add_column("Created")
    table.add_column("Target App")
    table.add_column("Device")
    table.add_column("Authorized By")
    for m in sessions:
        table.add_row(
            m.get("name", "?"),
            m.get("created", "-"),
            m.get("target", {}).get("bundle_id") or "-",
            m.get("device", {}).get("model") or "-",
            m.get("authorization", {}).get("authorized_by") or "[red]UNSET[/red]",
        )
    console.print(table)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
