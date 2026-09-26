"""Tampering: modify / delete / reorder / splice -> distinct verdicts."""

from __future__ import annotations

import json

from audit.hashing import payload_hash
from tests.conftest import log_case


def _seed(service, n: int = 5):
    for i in range(1, n + 1):
        service.append({
            "id": f"evt-{i}",
            "timestamp": f"2026-09-2{i}T10:00:00",
            "actor": "bob", "action": "update", "resource": f"/r/{i}",
            "detail": {"v": i},
        })


def _read_lines(service):
    with open(service.storage.log_path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _write_lines(service, lines):
    text = "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
                   for r in lines)
    with open(service.storage.log_path, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_detect_modified_record(service):
    _seed(service)
    lines = _read_lines(service)
    lines[2]["detail"]["v"] = 999  # silently alter content of seq 3
    _write_lines(service, lines)

    verdict = service.verify()
    log_case(
        "tamper_modify",
        {"target_seq": 3, "mutation": "detail.v 3 -> 999 (hash fields untouched)"},
        {"error_code": verdict.error_code, "error_seq": verdict.error_seq,
         "reason": verdict.reason},
        f"EXPECTED_FAIL[{verdict.error_code}]",
    )
    assert not verdict.ok
    assert verdict.error_code == "hash_mismatch"
    assert verdict.error_seq == 3


def test_detect_deleted_record(service):
    _seed(service)
    lines = _read_lines(service)
    del lines[1]  # remove seq 2
    _write_lines(service, lines)

    verdict = service.verify()
    log_case(
        "tamper_delete",
        {"deleted_seq": 2},
        {"error_code": verdict.error_code, "error_index": verdict.error_index,
         "reason": verdict.reason},
        f"EXPECTED_FAIL[{verdict.error_code}]",
    )
    assert not verdict.ok
    assert verdict.error_code == "missing_record"


def test_detect_reordered_records(service):
    _seed(service)
    lines = _read_lines(service)
    lines[0], lines[1] = lines[1], lines[0]  # physically swap seq 1 and 2
    _write_lines(service, lines)

    verdict = service.verify()
    log_case(
        "tamper_reorder",
        {"swap": "physical positions of seq 1 and seq 2"},
        {"error_code": verdict.error_code, "error_seq": verdict.error_seq,
         "reason": verdict.reason},
        f"EXPECTED_FAIL[{verdict.error_code}]",
    )
    assert not verdict.ok
    assert verdict.error_code == "ordering_error"


def test_detect_splice_with_recomputed_hash(service):
    """Sophisticated attacker edits seq 2 AND recomputes its own hash, but
    cannot fix seq 3's prev_hash without re-hashing the whole tail."""
    _seed(service)
    lines = _read_lines(service)
    from audit.normalization import canonicalize_stored
    rec = canonicalize_stored(lines[1])
    rec.detail["v"] = 777
    lines[1]["detail"]["v"] = 777
    lines[1]["record_hash"] = payload_hash(rec)  # attacker re-seals record
    _write_lines(service, lines)

    verdict = service.verify()
    log_case(
        "tamper_splice_resealed",
        {"target_seq": 2, "mutation": "content changed + own record_hash recomputed"},
        {"error_code": verdict.error_code, "error_seq": verdict.error_seq,
         "reason": verdict.reason},
        f"EXPECTED_FAIL[{verdict.error_code}]",
    )
    assert not verdict.ok
    assert verdict.error_code == "chain_break"
    assert verdict.error_seq == 3


def test_clean_chain_verifies(service):
    """Negative control: normal writes produce an explainable PASS."""
    _seed(service, 4)
    verdict = service.verify()
    log_case(
        "clean_chain",
        {"records": 4},
        verdict.to_dict(),
        f"PASS[{verdict.reason}]",
    )
    assert verdict.ok and verdict.total == 4
