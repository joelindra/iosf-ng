"""Report generator (Phase 5).

Outputs:
* interactive HTML (severity filter, collapsible evidence, redaction aware)
* PDF via headless Edge/Chrome (no heavy dependency), fallback: print to HTML

Templates live in report/templates/report.html.j2.
"""
from __future__ import annotations

import base64
import html as html_mod
import json
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.util import human_bytes, now_iso, redact_headers
from ..core.session import Session
from ..analyzer.model import Finding, SEVERITY_ORDER, SEVERITY_COLORS, OWASP_API_TOP10, severity_summary, redact_evidence

TEMPLATES = Path(__file__).resolve().parent / "templates"

EDGE_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/microsoft-edge",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["sev_color"] = lambda s: SEVERITY_COLORS.get(s, "#666")
    env.filters["human_bytes"] = human_bytes
    return env


def find_browser() -> str | None:
    for cand in EDGE_CANDIDATES:
        p = Path(cand)
        if p.exists():
            return str(p)
    for name in ("msedge", "google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


class ReportGenerator:
    def __init__(self, session: Session, findings: list[Finding]):
        self.session = session
        self.findings = findings

    # ------------------------------------------------------------------
    def build_context(self, store=None, include_raw: bool = False) -> dict[str, Any]:
        sev = severity_summary(self.findings)
        by_cat: dict[str, dict[str, Any]] = {}
        for f in self.findings:
            d = by_cat.setdefault(
                f.category,
                {"category": f.category, "name": OWASP_API_TOP10.get(f.category, f.category_name),
                 "count": 0, "findings": []},
            )
            d["count"] += 1
            d["findings"].append(f.to_dict())

        traffic_summary = None
        top_hosts = []
        endpoints = []
        if store is not None:
            traffic_summary = store.stats()
            top_hosts = store.host_summary()
            endpoints = store.endpoint_summary()[:80]

        meta = dict(self.session.meta)
        return {
            "meta": meta,
            "generated": now_iso(),
            "findings": [f.to_dict() for f in self.findings],
            "severity": sev,
            "severity_order": list(SEVERITY_ORDER.keys()),
            "severity_colors": SEVERITY_COLORS,
            "categories": sorted(by_cat.values(), key=lambda d: d["category"]),
            "owasp": OWASP_API_TOP10,
            "traffic_summary": traffic_summary,
            "top_hosts": top_hosts,
            "endpoints": endpoints,
            "include_raw": include_raw,
            "tool_version": getattr(__import__("iostester"), "__version__", "0.1.0"),
        }

    def render_html(self, store=None, include_raw: bool = False) -> str:
        ctx = self.build_context(store, include_raw)
        return _env().get_template("report.html.j2").render(**ctx)

    def write_html(self, out_path: Path, store=None, include_raw: bool = False) -> Path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(self.render_html(store, include_raw), encoding="utf-8")
        return out_path

    def write_pdf(self, html_path: Path, pdf_path: Path) -> Path:
        browser = find_browser()
        if not browser:
            raise RuntimeError(
                "No headless browser found for PDF export. Install Microsoft Edge, "
                "Chrome, or Chromium, or use --format html."
            )
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            browser,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--print-to-pdf-no-header",
            f"--print-to-pdf={pdf_path}",
            html_path.resolve().as_uri(),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if not pdf_path.exists():
            raise RuntimeError(
                f"PDF generation failed (exit {proc.returncode}): "
                f"{(proc.stderr or proc.stdout or '')[-400:]}"
            )
        return pdf_path

    def write_all(self, formats: list[str], store=None, include_raw: bool = False) -> dict[str, Path]:
        out_dir = self.session.report_dir
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        outputs: dict[str, Path] = {}
        html_path = out_dir / f"report-{stamp}.html"
        if "html" in formats or "pdf" in formats:
            self.write_html(html_path, store, include_raw)
            outputs["html"] = html_path
        if "pdf" in formats:
            pdf_path = out_dir / f"report-{stamp}.pdf"
            self.write_pdf(html_path, pdf_path)
            outputs["pdf"] = pdf_path
        return outputs

    def export_json(self, out_path: Path) -> Path:
        payload = {
            "generated": now_iso(),
            "session": self.session.meta,
            "findings": [f.to_dict() for f in self.findings],
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out_path
