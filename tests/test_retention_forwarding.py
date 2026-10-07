"""Retention vs. forwarding progress: expired-but-undelivered records are
never pruned; once the cursor catches up, pruning behaves exactly like
the pure time-based policy — also under concurrent prune/forward/append."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from audit.config import Settings
from audit.service import AuditService
from tests.conftest import log_case

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
OLD_TS = (NOW - timedelta(days=100)).isoformat()


class RecordingDownstream:
    def __init__(self):
        self.delivered: list[int] = []

    def send(self, record):
        self.delivered.append(record["seq"])


def _service(tmp_path, *, forward_enabled, downstream=None):
    return AuditService(
        Settings(data_dir=str(tmp_path / "data"), retention_days=30,
                 forward_enabled=forward_enabled, max_forward_attempts=2),
        downstream=downstream)


def _seed_old(service, n, start=1):
    for i in range(start, start + n):
        service.append({"id": f"id{i}", "timestamp": OLD_TS,
                        "actor": "a", "action": "act", "resource": "/r",
                        "detail": {}})


def test_expired_but_unforwarded_records_survive_prune(tmp_path):
    ds = RecordingDownstream()
    service = _service(tmp_path, forward_enabled=True, downstream=ds)
    _seed_old(service, 4)  # all expired, none forwarded yet

    result = service.prune(now=NOW)
    verdict = service.verify()
    log_case(
        "prune_blocked_by_forward_backlog",
        {"expired_records": 4, "forward_cursor": 0},
        {"prune_result": result, "verify": verdict.to_dict(),
         "surviving_seqs": [r["seq"] for r in service.list_records()]},
        "PASS: nothing pruned while downstream has acknowledged nothing",
    )
    assert result["pruned"] == 0 and result["rewritten"] is False
    assert [r["seq"] for r in service.list_records()] == [1, 2, 3, 4]
    assert verdict.ok


def test_prune_releases_records_as_cursor_advances(tmp_path):
    ds = RecordingDownstream()
    service = _service(tmp_path, forward_enabled=True, downstream=ds)
    _seed_old(service, 4)

    fwd = service.forward()  # deliver everything, cursor -> 4
    assert fwd["ok"] and ds.delivered == [1, 2, 3, 4]

    result = service.prune(now=NOW)
    verdict = service.verify()
    log_case(
        "prune_after_forward_caught_up",
        {"expired_records": 4, "forward_cursor": fwd["cursor_after"]},
        {"prune_result": result, "verify": verdict.to_dict(),
         "surviving": service.list_records()},
        "PASS: fully delivered prefix pruned, checkpoint-anchored chain ok",
    )
    assert result["pruned"] == 4 and result["kept"] == 0
    assert verdict.ok  # fully-pruned chain with checkpoint is a legal state


def test_prune_stops_at_first_unforwarded_record(tmp_path):
    ds = RecordingDownstream()
    service = _service(tmp_path, forward_enabled=True, downstream=ds)
    _seed_old(service, 5)

    # Deliver only seq 1..2 by hand-crafting the cursor through a forward
    # run against a downstream that accepts two then stays silent.
    class TwoThenDown:
        def __init__(self):
            self.n = 0

        def send(self, record):
            self.n += 1
            if self.n > 2:
                raise RuntimeError("downstream down after two")

    service._forwarder.downstream = TwoThenDown()
    fwd = service.forward()
    assert not fwd["ok"] and fwd["cursor_after"] == 2

    result = service.prune(now=NOW)
    verdict = service.verify()
    surviving = [r["seq"] for r in service.list_records()]
    log_case(
        "prune_partial_cursor",
        {"expired_records": 5, "forward_cursor": 2},
        {"prune_result": result, "surviving_seqs": surviving,
         "verify": verdict.to_dict()},
        "PASS: only the delivered prefix (1..2) pruned; 3..5 kept despite "
        "being expired",
    )
    assert result["pruned"] == 2 and result["checkpoint_seq"] == 2
    assert surviving == [3, 4, 5]
    assert verdict.ok

    # Once the backlog is delivered, the rest becomes prunable.
    service._forwarder.downstream = RecordingDownstream()
    assert service.forward()["ok"]
    result2 = service.prune(now=NOW)
    assert result2["pruned"] == 3
    assert service.verify().ok


def test_forwarding_disabled_keeps_pure_time_based_behavior(tmp_path):
    service = _service(tmp_path, forward_enabled=False)
    _seed_old(service, 3)
    result = service.prune(now=NOW)
    log_case(
        "prune_forwarding_disabled",
        {"expired_records": 3, "forward_enabled": False},
        {"prune_result": result},
        "PASS: identical to the pre-existing time-based policy",
    )
    assert result["pruned"] == 3
    assert service.verify().ok


def test_concurrent_prune_forward_append_no_loss_no_false_tamper(tmp_path):
    ds = RecordingDownstream()
    service = _service(tmp_path, forward_enabled=True, downstream=ds)
    _seed_old(service, 10)  # expired backlog

    errors = []

    def do_prune():
        try:
            service.prune(now=NOW)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def do_forward():
        try:
            service.forward()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def do_append(i):
        try:
            service.append({"id": f"fresh{i}", "timestamp": NOW.isoformat(),
                            "actor": "a", "action": "act", "resource": "/r",
                            "detail": {}})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=9) as pool:
        futures = []
        for _ in range(3):
            futures.append(pool.submit(do_prune))
            futures.append(pool.submit(do_forward))
        for i in range(30):
            futures.append(pool.submit(do_append, i))
        for f in futures:
            f.result()
    # Final catch-up so every record had the chance to be delivered.
    service.forward()

    verdict = service.verify()
    surviving = {r["seq"] for r in service.list_records()}
    delivered = set(ds.delivered)
    total = 10 + 30
    lost = [s for s in range(1, total + 1)
            if s not in surviving and s not in delivered]
    log_case(
        "prune_forward_append_concurrent",
        {"expired_backlog": 10, "fresh_writes": 30,
         "prune_threads": 3, "forward_threads": 3},
        {"errors": [str(e) for e in errors],
         "verify": verdict.to_dict(),
         "surviving": sorted(surviving),
         "delivered": sorted(delivered),
         "lost_seqs": lost},
        "PASS: no record lost, no false tamper verdict, chain verifies",
    )
    assert errors == []
    assert lost == []
    assert verdict.ok, verdict.reason
