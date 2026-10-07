"""Retention must cooperate with forward progress: expired records that
were not delivered downstream yet are kept; delivered ones prune as usual."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from audit.config import Settings
from audit.service import AuditService
from tests.conftest import log_case

NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


class CollectingDownstream:
    def __init__(self):
        self.delivered: list[str] = []

    def send(self, record):
        self.delivered.append(record["id"])


def _make(tmp_path, downstream=None, *, enabled=True):
    return AuditService(
        Settings(data_dir=str(tmp_path / "data"), retention_days=30,
                 forward_enabled=enabled, max_forward_attempts=3),
        downstream=downstream)


def _seed_old(service, n, start=1):
    for i in range(start, start + n):
        service.append({
            "id": f"old-{i}",
            "timestamp": (NOW - timedelta(days=100)).isoformat(),
            "actor": "a", "action": "act", "resource": "/r",
            "detail": {"i": i}})


def test_expired_unforwarded_records_survive_prune(tmp_path):
    ds = CollectingDownstream()
    service = _make(tmp_path, ds)
    _seed_old(service, 5)  # all expired, none forwarded yet

    first = service.prune(now=NOW)
    verdict_after_hold = service.verify()
    log_case(
        "prune_holds_unforwarded",
        {"expired_records": 5, "forwarded": 0},
        {"prune": first, "verify": verdict_after_hold.to_dict(),
         "surviving": [r["seq"] for r in service.list_records()]},
        "PASS: nothing pruned while downstream has acknowledged nothing",
    )
    assert first["pruned"] == 0 and first["held_for_forward"] == 5
    assert first["forward_cursor"] == 0
    assert verdict_after_hold.ok

    # Forward a prefix only (simulate partial progress by delivering the
    # first 3 via the real forwarder, then pruning).
    fwd = service.forward()
    assert fwd["sent"] == 5  # downstream healthy: everything goes
    second = service.prune(now=NOW)
    verdict_after_catchup = service.verify()
    log_case(
        "prune_after_forward_caught_up",
        {"delivered": ds.delivered},
        {"prune": second, "verify": verdict_after_catchup.to_dict()},
        "PASS: once delivered, expired records prune exactly as before",
    )
    assert second["pruned"] == 5 and second["held_for_forward"] == 0
    assert verdict_after_catchup.ok
    assert service.list_records() == []


def test_prune_respects_partial_forward_progress(tmp_path):
    ds = CollectingDownstream()
    service = _make(tmp_path, ds)
    _seed_old(service, 5)

    # Manually move the cursor to 3 (as if only seq 1..3 were acked) by
    # forwarding against a downstream that accepts exactly 3 records.
    class FirstThreeOnly:
        def __init__(self):
            self.count = 0

        def send(self, record):
            self.count += 1
            if self.count > 3:
                raise RuntimeError("downstream stops after 3")

    service._forwarder.downstream = FirstThreeOnly()
    fwd = service.forward()
    assert fwd["cursor_after"] == 3 and not fwd["ok"]

    result = service.prune(now=NOW)
    kept = [r["seq"] for r in service.list_records()]
    verdict = service.verify()
    log_case(
        "prune_partial_forward_progress",
        {"expired": 5, "acked_cursor": 3},
        {"prune": result, "kept_seqs": kept,
         "verify": verdict.to_dict()},
        "PASS: delivered prefix pruned, unforwarded tail held despite expiry",
    )
    assert result["pruned"] == 3
    assert result["held_for_forward"] == 2
    assert kept == [4, 5]
    assert verdict.ok  # shortened chain still verifies via checkpoint


def test_prune_forward_append_concurrently_no_loss_no_false_tamper(tmp_path):
    ds = CollectingDownstream()
    service = _make(tmp_path, ds)
    _seed_old(service, 30)

    def do_prune():
        return service.prune(now=NOW)

    def do_forward():
        return service.forward()

    def do_append(i):
        return service.append({
            "id": f"fresh-{i}", "timestamp": NOW.isoformat(),
            "actor": "a", "action": "act", "resource": "/r", "detail": {}})

    with ThreadPoolExecutor(max_workers=9) as pool:
        futs = []
        for _ in range(4):
            futs.append(pool.submit(do_prune))
            futs.append(pool.submit(do_forward))
        for i in range(10):
            futs.append(pool.submit(do_append, i))
        outcomes = [f.result() for f in futs]

    # Final settlement: forward whatever remains, then prune again.
    service.forward()
    service.prune(now=NOW)
    verdict = service.verify()
    on_disk = {r["seq"] for r in service.list_records()}
    delivered_ids = set(ds.delivered)
    # Every seq either survives on disk or was delivered downstream first.
    disk_ids = {r["id"] for r in service.list_records()}
    missing = {f"old-{i}" for i in range(1, 31)} - delivered_ids - disk_ids
    log_case(
        "prune_forward_append_concurrent",
        {"old_expired": 30, "fresh_writes": 10,
         "prune_rounds": 4, "forward_rounds": 5},
        {"verify": verdict.to_dict(),
         "delivered_count": len(delivered_ids),
         "on_disk_seqs": sorted(on_disk),
         "lost_records": sorted(missing),
         "fresh_all_present": all(
             f"fresh-{i}" in delivered_ids or f"fresh-{i}" in disk_ids
             for i in range(10))},
        "PASS: no record lost, no false tamper verdict under concurrency",
    )
    assert verdict.ok, verdict.reason
    assert not missing
    assert all(not f.get("error") for f in
               [o for o in outcomes if isinstance(o, dict)])


def test_prune_unchanged_when_forwarding_disabled(tmp_path):
    service = _make(tmp_path, enabled=False)
    _seed_old(service, 4)
    result = service.prune(now=NOW)
    log_case(
        "prune_forward_disabled",
        {"expired": 4, "forward_enabled": False},
        {"prune": result, "verify": service.verify().to_dict()},
        "PASS: plain time-based pruning, cursor not consulted",
    )
    assert result["pruned"] == 4
    assert result["forward_cursor"] is None
    assert result["held_for_forward"] == 0
    assert service.verify().ok
