"""Downstream failure: no loss, no duplicate delivery, backlog recovery."""

from __future__ import annotations

import os

from audit.config import Settings
from audit.forwarder import AuditForwarder
from audit.integrity import append_to_chain
from audit.normalization import normalize_input
from audit.service import AuditService
from tests.conftest import log_case


class ScriptedDownstream:
    """Fails for configured (seq -> remaining_failures); records every call."""

    def __init__(self):
        self.calls: list[str] = []
        self.delivered: list[str] = []
        self._fail_remaining: dict[int, int] = {}

    def fail_next(self, seq: int, times: int = 1):
        self._fail_remaining[seq] = times

    def send(self, record):
        self.calls.append(record["id"])
        left = self._fail_remaining.get(record["seq"], 0)
        if left > 0:
            self._fail_remaining[record["seq"]] = left - 1
            raise RuntimeError(f"simulated downstream outage for seq {record['seq']}")
        self.delivered.append(record["id"])


def _make_service(tmp_path, downstream):
    return AuditService(
        Settings(data_dir=str(tmp_path / "data"), retention_days=90,
                 forward_enabled=True, max_forward_attempts=3),
        downstream=downstream)


def _seed(service, n, start=1):
    for i in range(start, start + n):
        service.append({"id": f"id{i}", "timestamp": f"2026-09-2{i}T10:00:00",
                        "actor": "a", "action": "act", "resource": "/r",
                        "detail": {}})


def test_retry_succeeds_within_attempt_budget(tmp_path):
    ds = ScriptedDownstream()
    ds.fail_next(2, times=2)  # first two attempts fail, third succeeds
    service = _make_service(tmp_path, ds)
    _seed(service, 3)

    result = service.forward()
    log_case(
        "forward_retry_within_budget",
        {"records": 3, "fail_then_succeed": "seq2 fails attempts 1-2"},
        {"result": result, "calls": ds.calls, "delivered": ds.delivered},
        "PASS: all delivered exactly once after retries",
    )
    assert result["ok"] and result["sent"] == 3
    assert ds.delivered == ["id1", "id2", "id3"]
    # id2 invoked 3 times but accepted once; no duplicate delivery.
    assert ds.calls.count("id2") == 3
    assert ds.delivered.count("id2") == 1


def test_failure_pauses_then_backlog_recovers_no_loss_no_dup(tmp_path):
    ds = ScriptedDownstream()
    ds.fail_next(2, times=99)  # seq2 stays down
    service = _make_service(tmp_path, ds)
    _seed(service, 2)

    first = service.forward()
    assert not first["ok"]
    assert first["cursor_after"] == 1  # only seq1 acknowledged
    assert first["failures"][0]["seq"] == 2

    # Backlog grows while downstream is down (new writes keep succeeding).
    _seed(service, 2, start=3)  # new appends seq 3..4 during the outage
    pending_again = service.forward()
    assert not pending_again["ok"]
    assert pending_again["cursor_after"] == 1  # still blocked at seq2
    assert ds.delivered == ["id1"]  # seq3/4 must not skip the failed seq2

    # Downstream heals. A fresh forwarder process (restart) recovers the
    # backlog from the persisted cursor.
    ds2 = ScriptedDownstream()
    state_path = os.path.join(str(tmp_path / "data"), "forward.state")
    restarted = AuditForwarder(ds2, state_path=state_path, max_attempts=3)
    _cp, records = service.storage.load_all()
    recovered = restarted.forward_pending(records)

    log_case(
        "forward_outage_then_restart_recovery",
        {"backlog": 4, "outage": "seq2 hard down, then process restart"},
        {"before_heal_cursor": first["cursor_after"],
         "calls_before_heal": ds.calls,
         "recovered": recovered,
         "restart_delivered": ds2.delivered},
        "PASS: no loss (all 4), no dup (id1 not resent), in-order",
    )
    assert recovered["ok"] and recovered["sent"] == 3
    assert recovered["cursor_after"] == 4
    assert ds2.delivered == ["id2", "id3", "id4"]

    # Another forward call is a no-op: nothing resent.
    assert restarted.forward_pending(records)["sent"] == 0


def test_cursor_persists_across_restart_without_resend(tmp_path):
    ds = ScriptedDownstream()
    service = _make_service(tmp_path, ds)
    _seed(service, 3)
    service.forward()
    assert ds.delivered == ["id1", "id2", "id3"]

    ds2 = ScriptedDownstream()
    state_path = os.path.join(str(tmp_path / "data"), "forward.state")
    fw2 = AuditForwarder(ds2, state_path=state_path, max_attempts=3)
    _cp, records = service.storage.load_all()
    result = fw2.forward_pending(records)
    log_case(
        "forward_restart_idempotent",
        {"already_delivered": ["id1", "id2", "id3"]},
        {"cursor": fw2.load_state(), "result": result,
         "delivered_after_restart": ds2.delivered},
        "PASS: restart produced zero duplicate sends",
    )
    assert result["sent"] == 0 and ds2.delivered == []
