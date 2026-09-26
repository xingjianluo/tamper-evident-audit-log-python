"""Concurrent appends must not break the chain or duplicate seq."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from tests.conftest import log_case


def _payload(i: int) -> dict:
    return {
        "id": f"evt-{i:04d}",
        "timestamp": f"2026-09-26T10:{i % 60:02d}:00",
        "actor": "alice",
        "action": "login",
        "resource": "/console",
        "detail": {"index": i, "password": f"pw-{i}"},
    }


def test_concurrent_append_chain_intact(service):
    n = 50
    payloads = [_payload(i) for i in range(n)]

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(service.append, payloads))

    # Evidence: assigned seq and returned ids.
    seqs = sorted(r["seq"] for r in results)
    ids = sorted(r["id"] for r in results)

    verdict = service.verify()
    log_case(
        "concurrent_append",
        {"threads": 16, "records": n, "sample_input": _payload(0)},
        {"seqs_unique": len(set(seqs)) == n,
         "seqs_contiguous": seqs == list(range(1, n + 1)),
         "ids_unique": len(set(ids)) == n,
         "no_secret_in_response": all(
             r["detail"]["password"] == "__redacted__" for r in results),
         "verify": verdict.to_dict()},
        "PASS: chain intact, no duplicate seq, masked",
    )

    assert seqs == list(range(1, n + 1)), "sequence gap/duplicate under concurrency"
    assert len(set(ids)) == n
    assert verdict.ok, verdict.reason
    # Secrets must not come back through the API either.
    assert all(r["detail"]["password"] == "__redacted__" for r in results)


def test_concurrent_append_interleaved_with_verify(service):
    """A verify() running concurrently with appends must always observe a
    self-consistent chain (never a half-linked state)."""
    verdicts: list[tuple[bool, str]] = []
    stop = {"v": False}

    def verifier():
        while not stop["v"]:
            r = service.verify()
            # Empty chain before the first append is also a known state.
            assert r.ok or r.error_code == "empty_chain", r
            verdicts.append((r.ok, r.error_code))

    with ThreadPoolExecutor(max_workers=8) as pool:
        vf = pool.submit(verifier)
        list(pool.map(service.append,
                      [_payload(i) for i in range(40)]))
        stop["v"] = True
        vf.result(timeout=10)

    final = service.verify()
    log_case(
        "concurrent_append_vs_verify",
        {"records": 40, "workers": 8, "interleaved_observations": len(verdicts)},
        {"final_verify": final.to_dict(),
         "all_observations_consistent": all(
             ok or code == "empty_chain" for ok, code in verdicts)},
        "PASS: readers never observed a torn chain",
    )
    assert final.ok
