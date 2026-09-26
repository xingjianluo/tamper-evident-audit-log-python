"""Service entrypoint.

Run the HTTP API::

    uv run python main.py serve

Verify the local audit log from disk (exit code 0 = intact, 2 = tampered)::

    uv run python main.py verify
"""

import argparse
import json
import sys

import uvicorn
from fastapi import FastAPI

from audit.api import register_routes
from audit.config import load_settings
from audit.service import AuditService

app = FastAPI(title="tamper-evident-audit-log")
register_routes(app)


@app.get("/")
def read_root():
    return {"service": "tamper-evident-audit-log", "status": "ok"}


def _cmd_verify() -> int:
    service = AuditService(load_settings())
    result = service.verify()
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0 if result.ok else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Tamper-evident audit service")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("verify", help="verify the local audit chain and exit")
    sub.add_parser("serve", help="run the HTTP API (default)")
    args = parser.parse_args(argv)
    if args.command == "verify":
        return _cmd_verify()
    uvicorn.run(app, host="127.0.0.1", port=8000)
    return 0


if __name__ == "__main__":
    sys.exit(main())
