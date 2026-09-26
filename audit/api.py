"""HTTP API wiring for the existing FastAPI service."""

from __future__ import annotations


from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from audit.errors import AuditError
from audit.service import get_audit_service


def register_routes(app: FastAPI) -> None:
    @app.post("/audit/records")
    async def append_record(request: Request):
        payload = await request.json()
        return get_audit_service().append(payload)

    @app.get("/audit/records")
    async def list_records():
        return {"records": get_audit_service().list_records()}

    @app.get("/audit/verify")
    async def verify():
        return get_audit_service().verify().to_dict()

    @app.post("/audit/prune")
    async def prune():
        return get_audit_service().prune()

    @app.post("/audit/forward")
    async def forward():
        return get_audit_service().forward()

    @app.exception_handler(AuditError)
    async def handle_audit_error(_request: Request, exc: AuditError):
        status = 409 if exc.code == "sequence_conflict" else 400
        return JSONResponse(status_code=status,
                            content={"ok": False, "error": exc.code,
                                     "message": str(exc)})
