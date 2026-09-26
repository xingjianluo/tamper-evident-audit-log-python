"""Scenario: downstream failure: retry, no loss, no duplicate, backlog recovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from audit.chain import AuditChain
from audit.forwarder import ForwardError, Forwarder
from tests._case_log import log_case


def _seed(tmp_path: Path, n: int = 5) -> AuditChain:
    chain = AuditChain(tmp_path)
    for i in range(1, n + 1):
        chain.append({"actor": "u", "action": "a", "payload": {"i": i}})
    return chain


def test_failure_keeps_full_backlog_then_recovers(tmp_path: Path):
    chain = _seed(tmp_path)
    delivered: list[dict] = []
    state = {"down": True, "calls": 0}

    def flaky_send(batch):
        state["calls"] += 1
        if state["down"]:
            raise ConnectionError("downstream 500")
        delivered.extend(batch)

    fwd = Forwarder(chain, flaky_send, batch_size=2, max_retries=3)

    with pytest.raises(ForwardError) as exc:
        fwd.flush()
    basis1 = (f"send attempts while down={state['calls']} (=max_retries), "
              f"cursor stays 0, pending={exc.value.pending}")
    log_case("forward-down", "5 records, downstream always fails, max_retries=3",
             basis1,
             "PASS: nothing delivered, full backlog retained" if
             (state["calls"] == 3 and not delivered and exc.value.pending == 5) else "FAIL")
    assert state["calls"] == 3 and not delivered and exc.value.pending == 5

    # downstream recovers mid-run; new records also land meanwhile
    state["down"] = False
    chain.append({"actor": "u", "action": "a", "payload": {"i": 6}})
    sent = fwd.flush()
    seqs = [r["seq"] for r in delivered]
    basis2 = f"delivered={sent}, seqs={seqs}, unique={len(set(seqs)) == len(seqs)}"
    log_case("forward-recover", "downstream recovered + 1 new record appended",
             basis2,
             "PASS: backlog drained in order, no dup, no loss" if
             (sent == 6 and seqs == [1, 2, 3, 4, 5, 6] and fwd.pending() == 0) else "FAIL")
    assert sent == 6 and seqs == [1, 2, 3, 4, 5, 6] and fwd.pending() == 0

    # re-flush after complete: nothing is sent twice
    again = fwd.flush()
    log_case("forward-idempotent", "flush() again with no new data",
             f"second flush delivered {again}",
             "PASS: zero duplicates" if again == 0 else "FAIL")
    assert again == 0


def test_partial_run_resumes_at_cursor(tmp_path: Path):
    """Fail on batch 2 only: batch 1 stays delivered, resume continues at seq 3."""
    chain = _seed(tmp_path, n=4)
    delivered: list[dict] = []
    failed = {"done": False}

    def fail_second_batch(batch):
        if batch[0]["seq"] == 3 and not failed["done"]:
            failed["done"] = True
            raise TimeoutError("transient")
        delivered.extend(batch)

    fwd = Forwarder(chain, fail_second_batch, batch_size=2, max_retries=1)
    with pytest.raises(ForwardError):
        fwd.flush()
    first = [r["seq"] for r in delivered]
    recovered = fwd.flush()
    all_seqs = [r["seq"] for r in delivered]
    log_case("forward-resume",
             "batch [3,4] times out once; batch [1,2] was acked",
             f"after first flush={first}; recovered={recovered}; all={all_seqs}",
             "PASS: resumes exactly at seq 3" if
             (first == [1, 2] and recovered == 2 and all_seqs == [1, 2, 3, 4]) else "FAIL")
    assert first == [1, 2] and recovered == 2 and all_seqs == [1, 2, 3, 4]
