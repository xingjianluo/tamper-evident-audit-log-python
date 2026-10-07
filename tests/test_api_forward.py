"""API-triggered forwarding against a real local HTTP downstream: enabling
the switch + configuring a reachable URL makes POST /audit/forward actually
deliver the backlog, in order, with retry/recovery on short outages."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

import audit.service as service_module
from audit.config import Settings
from audit.service import AuditService
from tests.conftest import log_case


class _Handler(BaseHTTPRequestHandler):
    received: ClassVar[list[dict]] = []
    fail_with_500: ClassVar[bool] = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if self.fail_with_500:
            self.send_response(500)
            self.end_headers()
            return
        type(self).received.append(json.loads(body.decode("utf-8")))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture
def downstream_server():
    _Handler.received = []
    _Handler.fail_with_500 = False
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/ingest", _Handler
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


@pytest.fixture
def client(tmp_path, downstream_server):
    url, _handler = downstream_server
    svc = AuditService(Settings(
        data_dir=str(tmp_path / "data"), retention_days=90,
        forward_enabled=True, forward_url=url,
        max_forward_attempts=3, forward_timeout_seconds=2.0))
    old = service_module._service
    service_module._service = svc
    from main import app
    with TestClient(app) as c:
        yield c
    service_module._service = old


def _post(client, i, legacy=False):
    if legacy:
        payload = {"version": 0, "event_id": f"legacy-{i}",
                   "occurred_at": f"2026-09-2{i}T09:00:00",
                   "principal": "old-sys", "operation": "export",
                   "object": "/reports", "attrs": {"token": f"t-{i}"}}
    else:
        payload = {"id": f"evt-{i}", "timestamp": f"2026-09-2{i}T10:00:00",
                   "actor": "alice", "action": "login", "resource": "/vpn",
                   "detail": {"password": f"pw-{i}"}}
    resp = client.post("/audit/records", json=payload)
    assert resp.status_code == 200, resp.text


def test_api_triggered_forward_delivers_backlog_in_order(
        client, downstream_server):
    _url, handler = downstream_server
    for i in range(1, 4):
        _post(client, i)
    _post(client, 4, legacy=True)  # legacy record forwarded identically

    resp = client.post("/audit/forward")
    result = resp.json()
    received = handler.received
    log_case(
        "api_forward_real_downstream",
        {"appended": ["evt-1", "evt-2", "evt-3", "legacy-4(v0)"]},
        {"forward_result": result,
         "downstream_got_ids": [r["id"] for r in received],
         "downstream_got_seqs": [r["seq"] for r in received],
         "secret_leaks": [s for s in ("pw-1", "t-4")
                          if s in json.dumps(received)]},
        "PASS: backlog delivered over real HTTP, in seq order, masked",
    )
    assert resp.status_code == 200
    assert result["ok"] and result["sent"] == 4
    assert [r["seq"] for r in received] == [1, 2, 3, 4]
    assert [r["id"] for r in received] == ["evt-1", "evt-2", "evt-3",
                                           "legacy-4"]
    # The legacy record arrives normalized (canonical v1 form, masked).
    assert received[3]["version"] == 1
    assert received[3]["actor"] == "old-sys"
    assert received[3]["detail"]["token"] == "__redacted__"
    assert received[0]["detail"]["password"] == "__redacted__"

    # A second trigger is a no-op: nothing is redelivered.
    again = client.post("/audit/forward").json()
    assert again["sent"] == 0 and len(handler.received) == 4


def test_api_forward_outage_then_recovery_no_loss_no_dup(
        client, downstream_server):
    _url, handler = downstream_server
    _post(client, 1)
    _post(client, 2)

    handler.fail_with_500 = True  # downstream goes down
    down = client.post("/audit/forward").json()
    assert down["ok"] is False
    assert down["failures"] and down["failures"][0]["seq"] == 1
    assert handler.received == []

    _post(client, 3)  # backlog grows during the outage
    handler.fail_with_500 = False  # downstream heals
    recovered = client.post("/audit/forward").json()
    log_case(
        "api_forward_outage_recovery",
        {"outage": "HTTP 500 for first trigger", "backlog": 3},
        {"during_outage": {"ok": down["ok"], "failures": down["failures"]},
         "after_heal": recovered,
         "downstream_got": [(r["seq"], r["id"]) for r in handler.received]},
        "PASS: no loss, no duplicate, in-order after recovery",
    )
    assert recovered["ok"] and recovered["sent"] == 3
    assert [r["seq"] for r in handler.received] == [1, 2, 3]
    # Verify the chain itself is untouched by forwarding activity.
    assert client.get("/audit/verify").json()["ok"] is True


def test_api_forward_enabled_without_url_is_explainable(tmp_path):
    svc = AuditService(Settings(data_dir=str(tmp_path / "data"),
                                forward_enabled=True, forward_url=""))
    old = service_module._service
    service_module._service = svc
    from main import app
    try:
        with TestClient(app) as c:
            result = c.post("/audit/forward").json()
    finally:
        service_module._service = old
    log_case(
        "api_forward_no_url",
        {"forward_enabled": True, "forward_url": ""},
        result,
        "EXPECTED_FAIL[forward_url_not_configured]",
    )
    assert result["ok"] is False
    assert result["enabled"] is True
    assert result["reason"] == "forward_url_not_configured"
