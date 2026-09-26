"""Scenario: concurrent appends must keep the chain intact, no dup/gap seq."""

from __future__ import annotations

import threading
from pathlib import Path

from audit.chain import AuditChain
from audit.models import FailureReason
from tests._case_log import log_case, verdict_text


def test_concurrent_appends_keep_chain_intact(tmp_path: Path):
    chain = AuditChain(tmp_path, sensitive_fields=("token",))
    threads_n, per_thread = 32, 25
    inputs = {"threads": threads_n, "appends_per_thread": per_thread,
              "expected_total": threads_n * per_thread}

    def worker(tid: int):
        for i in range(per_thread):
            chain.append({"actor": f"t{tid}", "action": "do",
                          "payload": {"i": i, "token": f"secret-{tid}-{i}"}})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    seqs = sorted(r.seq for r in chain.records())
    unique_seqs = set(seqs)
    result = chain.verify()

    basis = {"stored_count": len(seqs), "unique_seq_count": len(unique_seqs),
             "seq_range": [seqs[0], seqs[-1]],
             "verification": verdict_text(result)}
    conclusion = ("PASS: seq 1..800 contiguous & unique, hash chain intact"
                  if len(seqs) == 800 and unique_seqs == set(range(1, 801))
                  and result.ok else "FAIL")
    log_case("concurrent-append", inputs, basis, conclusion)

    assert len(seqs) == 800
    assert unique_seqs == set(range(1, 801))  # no gap, no duplicate
    assert result.ok
    assert result.reason is FailureReason.OK
    raw = (tmp_path / "chain.jsonl").read_text(encoding="utf-8")
    assert "secret-" not in raw  # masked secrets never reach disk
