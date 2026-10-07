"""Cross-version ingest: legacy v0 and current v1 records enter through the
same entry, normalize to one canonical form, and verify under one standard."""

from __future__ import annotations

import json

import pytest

from audit.errors import SchemaValidationError
from tests.conftest import log_case


def _v1(i: int) -> dict:
    return {"id": f"v1-{i}", "timestamp": f"2026-09-2{i}T10:00:00",
            "actor": "alice", "action": "login", "resource": "/console",
            "detail": {"password": f"pw-{i}"}}


def _v0(i: int) -> dict:
    return {"version": 0, "event_id": f"v0-{i}",
            "occurred_at": f"2026-09-2{i}T09:00:00",
            "principal": "legacy-user", "operation": "export",
            "object": "/reports",
            "attrs": {"rows": i, "token": f"tok-{i}"}}


def test_mixed_generations_single_chain_uniform_verdict(service):
    appended = [service.append(p) for p in (_v0(1), _v1(2), _v0(3), _v1(4))]
    listing = service.list_records()
    verdict = service.verify()

    evidence = {
        "stored_versions": sorted({r["version"] for r in listing}),
        "seqs": [r["seq"] for r in listing],
        "legacy_record": next(r for r in listing if r["id"] == "v0-1"),
        "secret_leaks": [s for s in ("pw-2", "tok-1", "tok-3")
                         if s in json.dumps(listing)],
        "verify": verdict.to_dict(),
    }
    log_case(
        "mixed_v0_v1_chain",
        {"inputs": [_v0(1), _v1(2), _v0(3), _v1(4)]},
        evidence,
        "PASS: one canonical form, one verification standard, no leaks",
    )

    # One uniform stored form regardless of inbound generation.
    assert evidence["stored_versions"] == [1]
    assert [r["seq"] for r in listing] == [1, 2, 3, 4]
    # Legacy information is fully preserved under canonical names.
    legacy = evidence["legacy_record"]
    assert legacy["actor"] == "legacy-user"
    assert legacy["action"] == "export"
    assert legacy["resource"] == "/reports"
    assert legacy["timestamp"] == "2026-09-21T09:00:00"
    assert legacy["detail"]["rows"] == 1
    # Masking applies to legacy attrs exactly as to v1 detail.
    assert legacy["detail"]["token"] == "__redacted__"
    assert appended[1]["detail"]["password"] == "__redacted__"
    assert evidence["secret_leaks"] == []
    # Same verification standard for the mixed chain.
    assert verdict.ok and verdict.total == 4


def test_legacy_record_survives_disk_roundtrip_and_tamper_check(
        service, tmp_path):
    """A normalized legacy record is hashed/verified exactly like a v1 one:
    tampering with it is detected with the same error codes."""
    service.append(_v0(1))
    service.append(_v1(2))
    assert service.verify().ok

    # Tamper with the normalized legacy record on disk.
    log_path = tmp_path / "data" / "audit.log"
    lines = [json.loads(l) for l in
             log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines[0]["id"] == "v0-1" and lines[0]["version"] == 1
    lines[0]["actor"] = "forged-user"
    log_path.write_text(
        "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
                for r in lines), encoding="utf-8")

    verdict = service.verify()
    log_case(
        "legacy_record_tampered",
        {"mutation": "actor of normalized v0 record rewritten on disk"},
        {"error_code": verdict.error_code, "error_seq": verdict.error_seq,
         "reason": verdict.reason},
        f"EXPECTED_FAIL[{verdict.error_code}]",
    )
    assert not verdict.ok
    assert verdict.error_code == "hash_mismatch"
    assert verdict.error_seq == 1


def test_legacy_rejections_are_explicit_and_write_nothing(service):
    base = _v0(1)
    cases = [
        ("missing_legacy_field",
         {k: v for k, v in base.items() if k != "principal"},
         "missing_field"),
        ("illegal_legacy_value",
         {**base, "occurred_at": "not-a-time"}, "ISO-8601"),
        ("unknown_legacy_field",
         {**base, "mystery": 1}, "unknown_field"),
        ("unknown_version",
         {**_v1(2), "version": 7}, "unsupported_version"),
        ("empty_legacy_actor",
         {**base, "principal": "  "}, "must not be empty"),
    ]
    observed = []
    for name, payload, fragment in cases:
        with pytest.raises(SchemaValidationError) as exc:
            service.append(payload)
        assert fragment in str(exc.value), (name, exc.value)
        observed.append((name, str(exc.value)))

    verdict = service.verify()
    log_case(
        "legacy_schema_rejection",
        {"cases": [c[0] for c in cases]},
        {"rejected": observed, "chain_after": verdict.to_dict()},
        "PASS: all malformed/unknown inputs rejected, nothing written",
    )
    assert verdict.error_code == "empty_chain"
