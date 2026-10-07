"""HTTP-triggered forwarding: with the switch on and a reachable local
downstream URL configured, POST /audit/forward really delivers the
backlog in order; short outages retry and recover with no loss/dup."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

import audit.service as service_module
from audit.config import Settings
from audit.service import AuditService
from tests.conftest import log_case


class _Sink(BaseHTTPRequestHandler):
    """Collects POSTed records; can be told to refuse connections."""

    received: ClassVar[list[dict]] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        type(self).received.append(json.loads(body.decode("utf-8")))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture
def downstream_server():
    _Sink.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/ingest", _Sink.received
    server.shutdown()
    thread.join()


def _free_port() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    port = server.server_address[1]
    server.server_close()
    return port


def _client_for(tmp_path, **overrides):
    svc = AuditService(Settings(data_dir=str(tmp_path / "data"),
                                retention_days=90, **overrides))
    old = service_module._service
    service_module._service = svc
    from main import app
    client = TestClient(app)
    return client, old


def _append(client, i):
    resp = client.post("/audit/records", json={
        "id": f"e{i}", "timestamp": f"2026-10-0{min(i, 7)}T10:00:00",
        "actor": "a", "action": "act", "resource": "/r",
        "detail": {"token": f"secret-{i}"}})
    assert resp.status_code == 200, resp.text


def test_api_triggered_forward_really_delivers(tmp_path, downstream_server):
    url, received = downstream_server
    client, old = _client_for(tmp_path, forward_enabled=True, forward_url=url)
    try:
        for i in range(1, 4):
            _append(client, i)
        resp = client.post("/audit/forward")
        body = resp.json()
        log_case(
            "api_forward_real_delivery",
            {"trigger": "POST /audit/forward", "downstream": url,
             "backlog": 3},
            {"response": body,
             "downstream_got": [(r["seq"], r["id"]) for r in received]},
            "PASS: interface trigger delivered the backlog in order",
        )
        assert resp.status_code == 200
        assert body["ok"] and body["sent"] == 3 and body["cursor_after"] == 3
        assert [r["seq"] for r in received] == [1, 2, 3]
        # Downstream sees the same masked canonical form as the log.
        assert received[0]["detail"]["token"] == "__redacted__"
        assert "secret-1" not in json.dumps(received)
        # A second trigger is a no-op: nothing resent.
        again = client.post("/audit/forward").json()
        assert again["sent"] == 0 and len(received) == 3
    finally:
        service_module._service = old


def test_api_forward_outage_then_recovery_no_loss_no_dup(tmp_path):
    port = _free_port()  # nothing listening: connection refused
    url = f"http://127.0.0.1:{port}/ingest"
    client, old = _client_for(tmp_path, forward_enabled=True,
                              forward_url=url, max_forward_attempts=2,
                              forward_timeout_seconds=1.0)
    try:
        for i in range(1, 3):
            _append(client, i)
        down = client.post("/audit/forward").json()
        assert down["ok"] is False and down["cursor_after"] == 0
        assert down["failures"][0]["seq"] == 1

        # Downstream comes up; the next trigger must flush the backlog.
        _Sink.received = []
        server = ThreadingHTTPServer(("127.0.0.1", port), _Sink)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            _append(client, 3)  # backlog grows during the outage
            up = client.post("/audit/forward").json()
            log_case(
                "api_forward_outage_recovery",
                {"outage": "connection refused, then downstream heals",
                 "backlog": 3},
                {"while_down": {"ok": down["ok"],
                                "cursor": down["cursor_after"]},
                 "after_heal": up,
                 "downstream_got": [r["seq"] for r in _Sink.received]},
                "PASS: backlog flushed in order, no loss, no duplicate",
            )
            assert up["ok"] and up["sent"] == 3 and up["cursor_after"] == 3
            assert [r["seq"] for r in _Sink.received] == [1, 2, 3]
        finally:
            server.shutdown()
            thread.join()
    finally:
        service_module._service = old


def test_api_forward_enabled_without_url_is_explained(tmp_path):
    client, old = _client_for(tmp_path, forward_enabled=True, forward_url="")
    try:
        body = client.post("/audit/forward").json()
        log_case(
            "api_forward_not_configured",
            {"forward_enabled": True, "forward_url": ""},
            {"response": body},
            "EXPECTED_FAIL[forwarding_not_configured]",
        )
        assert body["ok"] is False
        assert body["reason"] == "forwarding_not_configured"
    finally:
        service_module._service = old
