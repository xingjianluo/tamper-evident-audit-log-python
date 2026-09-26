"""Retention: expired purge anchors the chain; un-forwarded records kept."""

from __future__ import annotations

from pathlib import Path

from audit.chain import AuditChain
from audit.models import FailureReason
from audit.retention import purge_expired
from tests._case_log import log_case

NOW = 1_000_000.0


def test_purge_anchors_and_remaining_chain_verifies(tmp_path: Path):
    chain = AuditChain(tmp_path)
    for ts in (100.0, 200.0, NOW - 3600):  # 2 expired, 1 fresh (<1d)
        chain.append({"actor": "u", "action": "a", "payload": {}, "ts": ts})
    purged = purge_expired(chain, retention_days=1, now=NOW, safe_seq=10**9)
    result = chain.verify()
    log_case("retention-purge",
             "ts=[100,200,now-1h], retention=1d",
             f"purged={purged}, anchor=seq2/hash, remaining={[r.seq for r in chain.records()]}",
             "PASS: 2 purged, chain verifies from anchor" if
             (purged == 2 and result.ok and [r.seq for r in chain.records()] == [3]) else "FAIL")
    assert purged == 2 and result.ok
    assert result.reason is FailureReason.OK


def test_unforwarded_expired_records_are_retained(tmp_path: Path):
    chain = AuditChain(tmp_path)
    for ts in (100.0, 200.0, NOW - 3600):
        chain.append({"actor": "u", "action": "a", "payload": {}, "ts": ts})
    purged = purge_expired(chain, retention_days=1, now=NOW, safe_seq=1)
    log_case("retention-backlog-guard",
             "all forwarded ack only up to safe_seq=1; seq2 expired but pending",
             f"purged={purged}, remaining seqs={[r.seq for r in chain.records()]}",
             "PASS: seq2 retained despite TTL expiry" if
             (purged == 1 and [r.seq for r in chain.records()] == [2, 3]) else "FAIL")
    assert purged == 1
    assert [r.seq for r in chain.records()] == [2, 3]
    assert chain.verify().ok


def test_tampering_after_purge_still_detected(tmp_path: Path):
    chain = AuditChain(tmp_path)
    for ts in (100.0, 200.0, NOW - 3600):
        chain.append({"actor": "u", "action": "a", "payload": {"v": 1}, "ts": ts})
    # seq3 is fresh anyway; ack cursor at seq2 exercises the backlog guard too
    purge_expired(chain, retention_days=1, now=NOW, safe_seq=2)
    # modify the one surviving (anchored) record
    rows = [__import__("json").loads(l) for l in chain.log_path.read_text().splitlines()]
    rows[0]["payload"]["v"] = 2
    import json
    chain.log_path.write_text(json.dumps(rows[0]) + "\n")
    result = chain.verify()
    log_case("retention-still-tamper-evident",
             "purged seq1-2, then modified surviving seq3",
             f"verification after tamper: {result.reason.value} @ seq{result.seq}",
             "PASS: modification after anchor detected" if
             result.reason is FailureReason.HASH_MISMATCH else "FAIL")
    assert result.reason is FailureReason.HASH_MISMATCH
