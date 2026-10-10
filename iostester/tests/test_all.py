"""Unit tests for iOSTester core, traffic store, splitters, profile, and OWASP engine."""
import json
import tempfile
from pathlib import Path

import pytest
import hyperframe.frame as hf
import hpack

from iostester.core.util import (
    shannon_entropy,
    redact_headers,
    decode_body,
    normalize_path_template,
    path_id_candidates,
)
from iostester.core.session import Session
from iostester.interceptor.capture import TrafficStore, H1Splitter, H2Splitter
from iostester.profile_gen.mobileconfig import (
    generate_ca,
    build_mobileconfig,
    ProfileOptions,
    ProxyConfig,
)
from iostester.analyzer.model import Finding, severity_summary
from iostester.analyzer.engine import RuleSet, Engine
from iostester.report.generator import ReportGenerator


def test_core_utils():
    # Entropy
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("AAAA") == 0.0
    assert shannon_entropy("abcdef123456") > 3.0

    # Header redaction
    hdrs = [["Authorization", "Bearer eyJhbGciOi..."], ["User-Agent", "App/1.0"], ["X-Api-Key", "secret123"]]
    redacted = redact_headers(hdrs)
    assert redacted[0][1].startswith("Bearer [REDACTED]")
    assert redacted[1][1] == "App/1.0"
    assert redacted[2][1] == "[REDACTED]"

    # Path normalization & BOLA id candidate
    assert normalize_path_template("/api/users/12345/profile") == "/api/users/{id}/profile"
    cands = path_id_candidates("/api/orders/9988", "page=1&account_id=42")
    assert ("path", "9988") in cands
    assert ("query", "42") in cands


def test_traffic_store_and_h1_splitter(tmp_path):
    db_file = tmp_path / "traffic.sqlite"
    store = TrafficStore(db_file)
    store.register_conn("c1", "test_session", "api.example.com", 443, "h1")

    splitter = H1Splitter(
        store,
        session="test_session",
        conn_id="c1",
        host="api.example.com",
        port=443,
    )

    req_data = b"GET /v1/users?id=10 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n"
    resp_data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"user\": \"alice\"}"

    splitter.feed_request(req_data)
    splitter.feed_response(resp_data)

    txs = store.iter_transactions()
    assert len(txs) == 1
    tx = txs[0]
    assert tx["method"] == "GET"
    assert tx["path"] == "/v1/users"
    assert tx["query"] == "id=10"
    assert tx["status"] == 200
    assert b"alice" in tx["resp_body"]
    store.close()


def test_h2_splitter(tmp_path):
    db_file = tmp_path / "h2.sqlite"
    store = TrafficStore(db_file)
    store.register_conn("c2", "h2_session", "api.example.com", 443, "h2")

    splitter = H2Splitter(
        store,
        session="h2_session",
        conn_id="c2",
        host="api.example.com",
        port=443,
    )

    # Encode HTTP/2 request headers
    enc = hpack.Encoder()
    req_hdrs = [
        (b":method", b"POST"),
        (b":path", b"/v1/transfer"),
        (b":scheme", b"https"),
        (b":authority", b"api.example.com"),
        (b"content-type", b"application/json"),
    ]
    hblock = enc.encode(req_hdrs)
    hframe = hf.HeadersFrame(stream_id=1, data=hblock)
    hframe.flags.add("END_HEADERS")
    req_bytes = hframe.serialize()

    # Add DATA frame
    dframe = hf.DataFrame(stream_id=1, data=b'{"amount": 500}')
    dframe.flags.add("END_STREAM")
    req_bytes += dframe.serialize()

    splitter.feed_request(req_bytes)

    # Encode HTTP/2 response headers
    resp_enc = hpack.Encoder()
    resp_hdrs = [
        (b":status", b"200"),
        (b"content-type", b"application/json"),
    ]
    resp_block = resp_enc.encode(resp_hdrs)
    rhframe = hf.HeadersFrame(stream_id=1, data=resp_block)
    rhframe.flags.add("END_HEADERS")
    resp_bytes = rhframe.serialize()

    resp_dframe = hf.DataFrame(stream_id=1, data=b'{"status": "ok"}')
    resp_dframe.flags.add("END_STREAM")
    resp_bytes += resp_dframe.serialize()

    splitter.feed_response(resp_bytes)

    txs = store.iter_transactions()
    assert len(txs) == 1
    tx = txs[0]
    assert tx["method"] == "POST"
    assert tx["path"] == "/v1/transfer"
    assert tx["status"] == 200
    assert b"amount" in tx["req_body"]
    assert b"ok" in tx["resp_body"]
    store.close()


def test_profile_generator(tmp_path):
    ca_dir = tmp_path / "ca"
    ca = generate_ca(ca_dir, common_name="Test CA")
    assert ca.ca_cert_path.exists()
    assert len(ca.ca_fingerprint_sha256) == 64

    profile_path = tmp_path / "test.mobileconfig"
    opts = ProfileOptions(
        display_name="Test Profile",
        proxy=ProxyConfig(host="192.168.1.50", port=8080),
        include_global_proxy=True,
    )
    build_mobileconfig(ca, opts, profile_path)
    assert profile_path.exists()
    content = profile_path.read_text(encoding="utf-8", errors="ignore")
    assert "com.apple.security.pkcs1" in content
    assert "com.apple.proxy.http.global" in content
    assert "192.168.1.50" in content

    # Test non-supervised default (CA only)
    profile_path_ca = tmp_path / "test_ca.mobileconfig"
    opts_ca = ProfileOptions(
        display_name="Test Profile CA",
        proxy=ProxyConfig(host="192.168.1.50", port=8080),
        include_global_proxy=False,
    )
    build_mobileconfig(ca, opts_ca, profile_path_ca)
    content_ca = profile_path_ca.read_text(encoding="utf-8", errors="ignore")
    assert "com.apple.security.pkcs1" in content_ca
    assert "com.apple.proxy.http.global" not in content_ca


def test_owasp_analyzer_engine(tmp_path):
    db_file = tmp_path / "test_engine.sqlite"
    store = TrafficStore(db_file)
    store.register_conn("c3", "test_scan", "api.target.com", 443, "h1")

    # Transaction 1: missing HSTS & token in URL
    store.start_tx("c3:1", "c3", "test_scan", "https", "api.target.com", 443, None)
    store.set_request("c3:1", "GET", "/api/v1/profile", "token=secret_xyz12345", "HTTP/1.1", [], None)
    store.set_response("c3:1", 200, "HTTP/1.1", [("Content-Type", "application/json")], b'{"name": "test"}')

    # Transaction 2: verbose error (500)
    store.start_tx("c3:2", "c3", "test_scan", "https", "api.target.com", 443, None)
    store.set_request("c3:2", "POST", "/api/v1/query", "", "HTTP/1.1", [], None)
    store.set_response(
        "c3:2", 500, "HTTP/1.1", [("Content-Type", "text/plain")],
        b"Exception in thread 'main' java.lang.NullPointerException\n  at com.app.Service.run(Service.java:42)"
    )

    rules = RuleSet.default()
    engine = Engine(store=store, session_name="test_scan", exclude_hosts=())
    findings = engine.run_passive(rules)

    rule_ids = {f.rule_id for f in findings}
    assert "API8-MISSING-HSTS" in rule_ids
    assert "API2-TOKEN-IN-URL" in rule_ids
    assert "API8-VERBOSE-ERRORS" in rule_ids
    store.close()


def test_report_generation(tmp_path):
    s = Session.create("test_report_sess", root=tmp_path)
    finding = Finding(
        id="F-0001",
        rule_id="API8-MISSING-HSTS",
        title="Missing Strict-Transport-Security",
        category="API8:2023",
        category_name="Security Misconfiguration",
        severity="low",
        confidence="high",
        description="Missing HSTS header.",
        evidence={"host": "api.example.com", "path": "/test"},
    )
    rep = ReportGenerator(s, [finding])
    html = rep.render_html()
    assert "API8:2023" in html
    assert "Missing Strict-Transport-Security" in html
    assert "test_report_sess" in html
