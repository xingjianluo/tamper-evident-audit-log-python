"""Retention pruning: shortened chain stays verifiable; writes during a
prune are neither deleted nor falsely flagged as tampered."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from audit.config import Settings
from audit.service import AuditService
from tests.conftest import log_case


def _append(service, i, ts):
    return service.append({"id": f"id{i}", "timestamp": ts,
                           "actor": "a", "action": "act", "resource": "/r",
                           "detail": {"i": i}})


def test_prune_keeps_chain_verifiable(tmp_path):
    now = datetime(2026, 9, 26, tzinfo=timezone.utc)
    service = AuditService(Settings(data_dir=str(tmp_path / "data"),
                                    retention_days=30))
    # 3 old, 2 fresh
    for i, day in enumerate([1, 2, 3, 4, 5], 1):
        ts = (now - timedelta(days=100 if i <= 3 else 1)).isoformat()
        _append(service, i, ts)

    result = service.prune(now=now)
    verdict = service.verify()
    log_case(
        "retention_prefix_prune",
        {"retention_days": 30, "old": 3, "fresh": 2},
        {"prune_result": result, "verify": verdict.to_dict(),
         "surviving_seqs": [r["seq"] for r in service.list_records()]},
        "PASS: 3 pruned with checkpoint, 2 kept and verifiable",
    )
    assert result["pruned"] == 3 and result["kept"] == 2
    assert result["checkpoint_seq"] == 3
    assert verdict.ok
    assert [r["seq"] for r in service.list_records()] == [4, 5]


def test_appends_during_prune_are_safe(tmp_path):
    now = datetime(2026, 9, 26, tzinfo=timezone.utc)
    service = AuditService(Settings(data_dir=str(tmp_path / "data"),
                                    retention_days=30))
    for i in range(1, 21):
        _append(service, i, (now - timedelta(days=100)).isoformat())

    pruned = []
    appended_seqs = []

    def do_prune():
        pruned.append(service.prune(now=now))

    # Hammer fresh writes concurrently with several prune rounds.
    with ThreadPoolExecutor(max_workers=8) as pool:
        pf = [pool.submit(do_prune) for _ in range(3)]
        futures = []
        for i in range(21, 41):
            ts = (now - timedelta(seconds=i)).isoformat()
            futures.append(pool.submit(_append, service, i, ts))
        for f in futures:
            appended_seqs.append(f.result()["seq"])
        for f in pf:
            f.result()

    verdict = service.verify()
    records = service.list_records()
    seqs = sorted(r["seq"] for r in records)
    # All 20 fresh writes survive: prune boundary only ever covered old seq.
    fresh_survive = all(s in seqs for s in range(21, 41))
    log_case(
        "retention_concurrent_writes",
        {"prunes": 3, "old_records": 20, "concurrent_fresh_writes": 20},
        {"verify": verdict.to_dict(),
         "appended_seqs": sorted(appended_seqs),
         "surviving_seqs": seqs,
         "fresh_writes_all_survive": fresh_survive,
         "prune_outcomes": pruned},
        "PASS: no fresh write deleted, no tamper verdict, chain verifies",
    )
    assert verdict.ok, verdict.reason
    assert sorted(appended_seqs) == list(range(21, 41))
    assert fresh_survive
