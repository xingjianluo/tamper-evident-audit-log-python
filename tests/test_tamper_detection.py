"""Scenario: human tampering must be detected with a distinct reason."""

from __future__ import annotations

import json
from pathlib import Path

from audit.chain import AuditChain
from audit.models import FailureReason
from tests._case_log import log_case, verdict_text


def _seed(tmp_path: Path) -> AuditChain:
    chain = AuditChain(tmp_path, sensitive_fields=("token",))
    for i in range(1, 6):
        chain.append({"actor": f"u{i}", "action": "act",
                      "payload": {"n": i, "token": f"TOPSECRET-{i}"}})
    return chain


def _raw_lines(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                    encoding="utf-8")


def test_baseline_is_intact(tmp_path: Path):
    chain = _seed(tmp_path)
    result = chain.verify()
    log_case("tamper-baseline", "5 normally appended records",
             verdict_text(result), "PASS: intact chain verifies ok" if result.ok else "FAIL")
    assert result.ok and result.reason is FailureReason.OK


def test_modification_detected_as_hash_mismatch(tmp_path: Path):
    chain = _seed(tmp_path)
    rows = _raw_lines(chain.log_path)
    rows[2]["payload"]["n"] = 999  # silently alter seq 3 content
    _write(chain.log_path, rows)

    result = chain.verify()
    log_case("tamper-modify",
             "payload.n of seq3 changed 3 -> 999",
             f"recompute sha256 over canonical(seq3) != stored hash; {verdict_text(result)}",
             f"PASS: detected at seq {result.seq}" if
             (not result.ok and result.reason is FailureReason.HASH_MISMATCH and result.seq == 3)
             else "FAIL")
    assert not result.ok
    assert result.reason is FailureReason.HASH_MISMATCH
    assert result.seq == 3


def test_deletion_detected_as_seq_missing(tmp_path: Path):
    chain = _seed(tmp_path)
    rows = _raw_lines(chain.log_path)
    _write(chain.log_path, rows[:1] + rows[2:])  # delete seq 2

    result = chain.verify()
    log_case("tamper-delete", "seq 2 line removed from chain.jsonl",
             f"expected seq 2 missing, no later line carries it; {verdict_text(result)}",
             "PASS: detected as seq_missing" if
             result.reason is FailureReason.SEQ_MISSING else "FAIL")
    assert result.reason is FailureReason.SEQ_MISSING


def test_reorder_detected_as_seq_reordered(tmp_path: Path):
    chain = _seed(tmp_path)
    rows = _raw_lines(chain.log_path)
    rows[1], rows[2] = rows[2], rows[1]  # swap seq 2 and 3
    _write(chain.log_path, rows)

    result = chain.verify()
    log_case("tamper-reorder", "lines for seq 2 and seq 3 swapped",
             f"at position 1 expected seq 2 but it exists later; {verdict_text(result)}",
             "PASS: detected as seq_reordered" if
             result.reason is FailureReason.SEQ_REORDERED else "FAIL")
    assert result.reason is FailureReason.SEQ_REORDERED


def test_replay_detected_as_seq_duplicate(tmp_path: Path):
    chain = _seed(tmp_path)
    rows = _raw_lines(chain.log_path)
    rows.insert(2, dict(rows[1]))  # replay/copy seq 2
    _write(chain.log_path, rows)

    result = chain.verify()
    log_case("tamper-replay", "an extra copy of the seq 2 line inserted",
             f"seq 2 appears again after being consumed; {verdict_text(result)}",
             "PASS: detected as seq_duplicate" if
             result.reason is FailureReason.SEQ_DUPLICATE else "FAIL")
    assert result.reason is FailureReason.SEQ_DUPLICATE


def test_garbage_line_detected_as_schema_error(tmp_path: Path):
    chain = _seed(tmp_path)
    with open(chain.log_path, "a", encoding="utf-8") as f:
        f.write('{"seq": 6, "broken": true\n')
    result = chain.verify()
    log_case("tamper-garbage", "a malformed JSON line appended",
             f"line cannot be decoded; {verdict_text(result)}",
             "PASS: detected as schema_error" if
             result.reason is FailureReason.SCHEMA_ERROR else "FAIL")
    assert result.reason is FailureReason.SCHEMA_ERROR


def test_sensitive_value_never_persisted_or_returned(tmp_path: Path):
    chain = _seed(tmp_path)
    disk = chain.log_path.read_text(encoding="utf-8")
    api_view = json.dumps([r.payload for r in chain.records()])
    result = chain.verify()
    log_case("mask-integrity",
             "records contain token=TOPSECRET-* in sensitive_fields",
             "secrets masked before hashing; disk/API checked for raw secret; "
             f"verification {result.reason.value}",
             "PASS: masked on disk & API yet chain verifies" if
             ("TOPSECRET" not in disk and "TOPSECRET" not in api_view and result.ok) else "FAIL")
    assert "TOPSECRET" not in disk
    assert "TOPSECRET" not in api_view
    assert result.ok
