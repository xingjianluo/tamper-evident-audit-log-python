"""Integration through the FastAPI entry: append/verify/retention/forward."""

from __future__ import annotations

import main
from audit.forwarder import Forwarder
from fastapi.testclient import TestClient
from tests._case_log import log_case


def setup_function(_):
    # point the module-level chain at an isolated empty data dir per test
    import tempfile
    from pathlib import Path
    main.chain = __import__("audit.chain", fromlist=["AuditChain"]).AuditChain(
        Path(tempfile.mkdtemp()), sensitive_fields=main.config.sensitive_fields)


client = TestClient(main.app)


def test_append_and_verify_endpoints():
    body = {"actor": "u1", "action": "login",
            "payload": {"token": "hunter2", "ip": "10.0.0.1"}}
    r = client.post("/audit/records", json=body)
    verify = client.get("/audit/verify").json()
    listed = client.get("/audit/records").json()["records"]
    log_case("api-append", body,
             f"POST /audit/records -> {r.status_code}; verify -> {verify}",
             f"PASS: {r.json()['ok']}, masked={listed[0]['payload']}")
    assert r.status_code == 200 and r.json()["ok"]
    assert verify["ok"] and verify["reason"] == "ok"
    assert listed[0]["payload"]["token"] == "***REDACTED***"
    assert "hunter2" not in str(listed)


def test_invalid_record_returns_422_with_kind():
    body = {"actor": "u1", "payload": {}}  # missing 'action'
    r = client.post("/audit/records", json=body)
    log_case("api-422", body,
             f"HTTP {r.status_code}, body={r.json()}",
             f"PASS: kind={r.json().get('kind')}" if r.status_code == 422 else "FAIL")
    assert r.status_code == 422
    assert r.json()["kind"] == "missing_field"


def test_verify_endpoint_reports_tamper(tmp_path, monkeypatch):
    import json
    main.chain = __import__("audit.chain", fromlist=["AuditChain"]).AuditChain(tmp_path)
    for i in range(3):
        client.post("/audit/records", json={"actor": "u", "action": "a",
                                            "payload": {"i": i}})
    rows = [json.loads(l) for l in main.chain.log_path.read_text().splitlines()]
    del rows[1]
    main.chain.log_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    r = client.get("/audit/verify").json()
    log_case("api-tamper", "deleted seq 2 directly on disk",
             f"verify response={r}",
             f"PASS: reason={r['reason']}" if r["reason"] == "seq_missing" else "FAIL")
    assert r["ok"] is False and r["reason"] == "seq_missing"


def test_forward_run_success_and_failure(monkeypatch):
    monkeypatch.setattr(main.config, "forward_url", "http://downstream/ingest")
    delivered = []
    state = {"down": True}

    def fake_forwarder():
        def sender(batch):
            if state["down"]:
                raise ConnectionError("downstream down")
            delivered.extend(batch)
        return Forwarder(main.chain, sender, batch_size=10, max_retries=1)

    monkeypatch.setattr(main, "_forwarder", fake_forwarder)
    client.post("/audit/records", json={"actor": "u", "action": "a", "payload": {}})

    bad = client.post("/audit/forward/run")
    state["down"] = False
    good = client.post("/audit/forward/run")
    log_case("api-forward", "1 record; downstream down then up",
             f"down -> HTTP {bad.status_code} {bad.json()}; "
             f"up -> HTTP {good.status_code} {good.json()}",
             "PASS: 502 with pending=1 then 200 with delivered=1" if
             (bad.status_code == 502 and bad.json()["pending"] == 1
              and good.status_code == 200 and good.json()["delivered"] == 1) else "FAIL")
    assert bad.status_code == 502 and bad.json()["pending"] == 1
    assert good.status_code == 200 and good.json()["delivered"] == 1
    assert [r["seq"] for r in delivered] == [1]


def test_forward_unconfigured_returns_503(monkeypatch):
    monkeypatch.setattr(main.config, "forward_url", None)
    r = client.post("/audit/forward/run")
    log_case("api-forward-unconfigured", "forward_url is None",
             f"HTTP {r.status_code} {r.json()}",
             "PASS: 503 backlog retained" if r.status_code == 503 else "FAIL")
    assert r.status_code == 503
