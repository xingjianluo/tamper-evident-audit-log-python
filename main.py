"""FastAPI service entry with the tamper-evident audit chain integrated."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib import request as urlrequest

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from audit.chain import AuditChain
from audit.config import AuditConfig
from audit.forwarder import ForwardError, Forwarder
from audit.normalize import SchemaError
from audit.retention import purge_expired

config = AuditConfig(data_dir=Path("data"))
chain = AuditChain(config.data_dir, sensitive_fields=config.sensitive_fields)


def _http_sender(url: str):
    """Build an ack-based downstream sender (POST JSON batch to ``url``)."""

    def send(batch: list[dict[str, Any]]) -> None:
        body = json.dumps({"records": batch}, ensure_ascii=False).encode("utf-8")
        req = urlrequest.Request(url, data=body, headers={"Content-Type": "application/json"},
                                 method="POST")
        with urlrequest.urlopen(req, timeout=5) as resp:
            if resp.status >= 300:
                raise ConnectionError(f"downstream status {resp.status}")

    return send


def _forwarder() -> Forwarder:
    return Forwarder(chain, _http_sender(config.forward_url),
                     batch_size=config.forward_batch_size,
                     max_retries=config.forward_max_retries)


app = FastAPI(title="tamper-evident-audit-log")


@app.get("/")
def read_root():
    return {"service": "tamper-evident-audit-log", "records": len(chain.records())}


@app.post("/audit/records")
def append_record(body: dict[str, Any]):
    """Append one audit record. Sensitive payload fields are masked on store.

    422 with a machine-readable ``kind`` when normalization fails.
    """
    try:
        rec = chain.append(body)
    except SchemaError as exc:
        return JSONResponse(status_code=422,
                            content={"ok": False, "kind": exc.kind, "detail": str(exc)})
    return {"ok": True, "record": asdict(rec)}


@app.get("/audit/records")
def list_records():
    """List stored records; sensitive values are never returned (masked at write time)."""
    return {"ok": True, "records": [asdict(r) for r in chain.records()]}


@app.get("/audit/verify")
def verify_chain():
    """Run local integrity verification and return the distinguishable verdict."""
    result = chain.verify()
    return {"ok": result.ok, "checked": result.checked,
            "reason": result.reason.value, "detail": result.detail, "seq": result.seq}


@app.post("/audit/retention/run")
def run_retention():
    """Purge records beyond the retention window.

    Records still pending downstream forwarding are kept (no loss); purged
    records leave an anchor so verification remains conclusive.
    """
    purged = purge_expired(chain, config.retention_days,
                           safe_seq=_forwarder().cursor())
    return {"ok": True, "purged": purged,
            "verification": {"ok": chain.verify().ok}}


@app.post("/audit/forward/run")
def run_forward():
    """Drain the forwarding backlog into the configured downstream."""
    if not config.forward_url:
        return JSONResponse(
            status_code=503,
            content={"ok": False, "detail": "forward_url is not configured; backlog retained"})
    fwd = _forwarder()
    try:
        delivered = fwd.flush()
    except ForwardError as exc:
        return JSONResponse(status_code=502, content={
            "ok": False, "delivered": exc.delivered, "pending": exc.pending,
            "detail": str(exc)})
    return {"ok": True, "delivered": delivered, "pending": fwd.pending()}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
