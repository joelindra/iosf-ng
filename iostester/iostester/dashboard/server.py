"""Lightweight FastAPI web dashboard (Phase 6 stretch goal).

Displays live transactions, host statistics, and findings in real-time.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from ..core.session import Session
from ..interceptor.capture import TrafficStore
from ..analyzer.model import load_findings

app = FastAPI(title="iOSTester Live Dashboard", version="0.1.0")

CURRENT_SESSION: Session | None = None


def set_active_session(s: Session) -> None:
    global CURRENT_SESSION
    CURRENT_SESSION = s


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    html_path = Path(__file__).resolve().parent / "index.html"
    if html_path.exists():
        return html_path.read_text(encoding="utf-8")
    return "<h1>iOSTester Dashboard</h1><p>No index.html template found.</p>"


@app.get("/api/stats")
def api_stats() -> dict[str, Any]:
    if not CURRENT_SESSION or not CURRENT_SESSION.db_path.exists():
        return {"transactions": 0, "hosts": 0, "paths": 0}
    store = TrafficStore(CURRENT_SESSION.db_path)
    try:
        return store.stats()
    finally:
        store.close()


@app.get("/api/transactions")
def api_transactions(limit: int = 50) -> list[dict[str, Any]]:
    if not CURRENT_SESSION or not CURRENT_SESSION.db_path.exists():
        return []
    store = TrafficStore(CURRENT_SESSION.db_path)
    try:
        return store.iter_transactions(limit=limit, order="ts DESC")
    finally:
        store.close()


@app.get("/api/findings")
def api_findings() -> list[dict[str, Any]]:
    if not CURRENT_SESSION or not CURRENT_SESSION.findings_path.exists():
        return []
    return [f.to_dict() for f in load_findings(CURRENT_SESSION.findings_path)]
