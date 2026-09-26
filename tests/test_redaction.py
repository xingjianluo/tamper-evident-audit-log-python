"""Masking & format compatibility: secrets never hit disk/responses,
masked records still verify, malformed versions are rejected not dropped."""

from __future__ import annotations

import json

import pytest

from audit.errors import SchemaValidationError
from tests.conftest import log_case

SECRETS = {"password": "hunter2", "api_key": "AKIA-SECRET", "token": "t.k.jwt"}


def test_sensitive_fields_masked_and_verifies(service, tmp_path):
    payload = {
        "id": "evt-1", "timestamp": "2026-09-26T10:00:00",
        "actor": "carol", "action": "login", "resource": "/vpn",
        "detail": {"nested": {"user": {"password": "hunter2"}},
                   "api_key": "AKIA-SECRET", "token": "t.k.jwt",
                   "safe": "keep-me", "list": [{"email": "a@b.c"}]},
    }
    result = service.append(payload)
    verdict = service.verify()

    # Evidence 1: response carries no secret material.
    response_blob = json.dumps(service.list_records(), ensure_ascii=False)
    # Evidence 2: raw bytes on disk carry no secret material.
    disk_blob = (tmp_path / "data" / "audit.log").read_text(encoding="utf-8")

    evidence = {
        "returned_detail": result["detail"],
        "secret_in_response": [s for s in SECRETS.values() if s in response_blob],
        "secret_on_disk": [s for s in SECRETS.values() if s in disk_blob],
        "non_sensitive_kept": result["detail"]["safe"] == "keep-me",
        "verify": verdict.to_dict(),
    }
    log_case("redaction", payload, evidence,
             "PASS: masked, verifiable, safe fields retained")

    assert evidence["secret_in_response"] == []
    assert evidence["secret_on_disk"] == []
    assert result["detail"]["api_key"] == "__redacted__"
    assert result["detail"]["nested"]["user"]["password"] == "__redacted__"
    assert result["detail"]["list"][0]["email"] == "__redacted__"
    assert result["detail"]["safe"] == "keep-me"
    assert verdict.ok


def test_unknown_missing_illegal_fields_are_rejected(service):
    base = {"id": "e", "timestamp": "2026-09-26T10:00:00", "actor": "a",
            "action": "x", "resource": "/r"}

    cases: list[tuple[str, dict, str]] = [
        ("unknown_field", {**base, "unexpected": 1}, "unknown_field"),
        ("missing_field", {"id": "e", "actor": "a"}, "missing_field"),
        ("bad_timestamp", {**base, "timestamp": "not-a-time"}, "ISO-8601"),
        ("unsupported_version", {**base, "version": 99}, "unsupported_version"),
        ("empty_actor", {**base, "actor": "  "}, "must not be empty"),
        ("non_string_action", {**base, "action": 7}, "must be a string"),
        ("detail_not_object", {**base, "detail": [1, 2]}, "must be an object"),
    ]
    observed = []
    for name, payload, fragment in cases:
        with pytest.raises(SchemaValidationError) as exc:
            service.append(payload)
        assert fragment in str(exc.value), (name, exc.value)
        observed.append((name, exc.value.code))
    # Nothing was written by rejected appends.
    verdict = service.verify()
    log_case("schema_rejection", {"cases": [c[0] for c in cases]},
             {"rejected": observed,
              "chain_after_rejections": verdict.to_dict()},
             f"PASS: {len(cases)} malformed inputs rejected, chain still empty")
    assert verdict.error_code == "empty_chain"


def test_explicit_v1_records_normalize_consistently(service):
    """Records carrying an explicit older/current version are normalized
    the same way as version-less current records."""
    payload = {"id": "e1", "version": 1, "timestamp": "2026-09-26T10:00:00",
               "actor": "a", "action": "x", "resource": "/r",
               "detail": {"password": "p"}}
    r1 = service.append(payload)
    r2 = service.append({**payload, "id": "e2", "version": 1})
    assert r1["version"] == r2["version"] == 1
    assert r1["detail"] == r2["detail"] == {"password": "__redacted__"}
    assert service.verify().ok
