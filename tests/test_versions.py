"""Cross-version intake: legacy v0 and current v1 records normalize onto
one canonical semantics; the mixed chain stays verifiable and malformed
inputs of either generation are rejected, never silently dropped/filled."""

from __future__ import annotations

import json

import pytest

from audit.errors import SchemaValidationError
from tests.conftest import log_case

LEGACY_OK = {
    "version": 0,
    "event_id": "legacy-1",
    "at": "2026-09-20T08:30:00",
    "user": "legacy-user",
    "op": "export",
    "target": "/reports/daily",
    "meta": {"rows": 42, "password": "legacy-secret"},
}

V1_OK = {
    "id": "cur-1", "timestamp": "2026-09-21T09:00:00",
    "actor": "carol", "action": "login", "resource": "/vpn",
    "detail": {"token": "cur-secret"},
}


def test_legacy_record_normalizes_to_canonical_semantics(service, tmp_path):
    result = service.append(dict(LEGACY_OK))
    verdict = service.verify()
    disk_blob = (tmp_path / "data" / "audit.log").read_text(encoding="utf-8")
    log_case(
        "legacy_v0_normalize",
        LEGACY_OK,
        {"stored_record": result, "verify": verdict.to_dict(),
         "secret_on_disk": "legacy-secret" in disk_blob},
        "PASS: v0 fields mapped 1:1 onto canonical semantics, masked, verified",
    )
    # Every piece of legacy information survives under the canonical name.
    assert result["version"] == 0
    assert result["id"] == "legacy-1"
    assert result["timestamp"] == "2026-09-20T08:30:00"
    assert result["actor"] == "legacy-user"
    assert result["action"] == "export"
    assert result["resource"] == "/reports/daily"
    assert result["detail"]["rows"] == 42
    # Legacy meta participates in masking exactly like v1 detail.
    assert result["detail"]["password"] == "__redacted__"
    assert "legacy-secret" not in disk_blob
    assert verdict.ok


def test_mixed_generations_one_chain_one_standard(service):
    service.append(dict(LEGACY_OK))                      # v0
    service.append(dict(V1_OK))                          # v1 (implicit)
    service.append({**dict(LEGACY_OK), "event_id": "legacy-2",
                    "at": "2026-09-22T10:00:00"})        # v0 again
    service.append({**dict(V1_OK), "id": "cur-2", "version": 1})

    listing = service.list_records()
    verdict = service.verify()
    log_case(
        "mixed_version_chain",
        {"appended": ["v0", "v1-implicit", "v0", "v1-explicit"]},
        {"seqs": [r["seq"] for r in listing],
         "versions": [r["version"] for r in listing],
         "schema_keys_uniform": {tuple(sorted(r)) for r in listing},
         "verify": verdict.to_dict()},
        "PASS: one chain, one on-disk schema, one verification standard",
    )
    assert [r["seq"] for r in listing] == [1, 2, 3, 4]
    assert [r["version"] for r in listing] == [0, 1, 0, 1]
    # Identical canonical key set for every record regardless of source.
    assert len({tuple(sorted(r)) for r in listing}) == 1
    assert verdict.ok and verdict.total == 4
    # Listing of a legacy-origin record shows canonical names only.
    assert listing[0]["actor"] == "legacy-user"
    assert "user" not in listing[0] and "meta" not in listing[0]


def test_legacy_origin_records_detect_tampering(service, tmp_path):
    service.append(dict(LEGACY_OK))
    service.append(dict(V1_OK))
    log_path = tmp_path / "data" / "audit.log"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["actor"] = "forged-user"  # tamper with the legacy-origin record
    lines[0] = json.dumps(first, ensure_ascii=False)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verdict = service.verify()
    log_case(
        "legacy_record_tamper",
        {"tampered": "actor of the v0-origin record on disk"},
        {"verify": verdict.to_dict()},
        f"EXPECTED_FAIL[{verdict.error_code}]",
    )
    assert not verdict.ok
    assert verdict.error_code == "hash_mismatch"
    assert verdict.error_seq == 1


def test_legacy_malformed_payloads_are_rejected(service):
    cases: list[tuple[str, dict, str]] = [
        ("legacy_unknown_field",
         {**LEGACY_OK, "legacy_extra": 1}, "unknown_field"),
        ("legacy_canonical_name_not_accepted",
         {**LEGACY_OK, "actor": "mallory"}, "unknown_field"),
        ("legacy_missing_field",
         {k: v for k, v in LEGACY_OK.items() if k != "user"},
         "missing_field"),
        ("legacy_bad_timestamp",
         {**LEGACY_OK, "at": "yesterday"}, "ISO-8601"),
        ("legacy_empty_value",
         {**LEGACY_OK, "op": "  "}, "must not be empty"),
        ("legacy_meta_not_object",
         {**LEGACY_OK, "meta": [1, 2]}, "must be an object"),
        ("unknown_version",
         {**V1_OK, "version": 7}, "unsupported_version"),
    ]
    observed = []
    for name, payload, fragment in cases:
        with pytest.raises(SchemaValidationError) as exc:
            service.append(payload)
        assert fragment in str(exc.value), (name, exc.value)
        observed.append((name, str(exc.value).split(":")[0]))
    verdict = service.verify()
    log_case(
        "legacy_schema_rejection",
        {"cases": [c[0] for c in cases]},
        {"rejected": observed, "chain_after": verdict.to_dict()},
        f"PASS: {len(cases)} malformed inputs rejected, nothing written",
    )
    assert verdict.error_code == "empty_chain"
