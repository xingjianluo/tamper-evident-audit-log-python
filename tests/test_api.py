"""End-to-end API smoke tests against the real FastAPI app."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import audit.service as service_module
from audit.config import Settings
from audit.service import AuditService
from tests.conftest import log_case


@pytest.fixture
def client(tmp_path):
    svc = AuditService(Settings(data_dir=str(tmp_path / "data"),
                                retention_days=90))
    # Point the FastAPI singleton at the isolated test service.
    old = service_module._service
    service_module._service = svc
    from main import app
    with TestClient(app) as c:
        yield c
    service_module._service = old


def test_api_append_and_verify(client):
    payload = {"id": "evt-1", "timestamp": "2026-09-26T10:00:00",
               "actor": "dave", "action": "login", "resource": "/vpn",
               "detail": {"password": "topsecret"}}
    r1 = client.post("/audit/records", json=payload)
    assert r1.status_code == 200, r1.text
    body = r1.json()

    r2 = client.post("/audit/records", json={
        "id": "evt-2", "timestamp": "2026-09-26T10:01:00",
        "actor": "dave", "action": "logout", "resource": "/vpn",
        "detail": {}})
    assert r2.status_code == 200

    listing = client.get("/audit/records").json()["records"]
    verify = client.get("/audit/verify").json()
    log_case(
        "api_append_verify",
        payload,
        {"first_record": body, "verify": verify,
         "secret_in_listing": "topsecret" in str(listing)},
        f"PASS: {verify['reason']}",
    )
    assert body["seq"] == 1 and body["prev_hash"] == "0" * 64
    assert body["detail"]["password"] == "__redacted__"
    assert verify["ok"] and verify["total"] == 2
    assert "topsecret" not in str(listing)


def test_api_rejects_bad_payload_with_distinct_error(client):
    resp = client.post("/audit/records",
                       json={"id": "x", "actor": "a"})  # missing fields
    verdict = resp.json()
    log_case(
        "api_bad_payload",
        {"id": "x", "actor": "a"},
        {"http_status": resp.status_code, "body": verdict},
        f"EXPECTED_FAIL[{verdict['error']}]",
    )
    assert resp.status_code == 400
    assert verdict["ok"] is False
    assert verdict["error"] == "schema_validation_error"


def test_api_prune_and_forward_endpoints(client):
    client.post("/audit/records", json={
        "id": "e", "timestamp": "2026-09-26T10:00:00",
        "actor": "a", "action": "x", "resource": "/r", "detail": {}})
    prune = client.post("/audit/prune")
    assert prune.status_code == 200 and prune.json()["pruned"] == 0
    fwd = client.post("/audit/forward")
    # Forwarding is not enabled in the default test settings: explainable.
    assert fwd.json()["enabled"] is False
