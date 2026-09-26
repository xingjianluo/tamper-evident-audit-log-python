"""Chain construction and integrity verification."""

from __future__ import annotations

from audit.models import AuditRecord, Checkpoint, VerifyResult
from audit.hashing import GENESIS_HASH, payload_hash
from audit.errors import (
    ChainBreakError, CheckpointMismatchError, DuplicateSequenceError,
    EmptyChainError, HashMismatchError, MissingRecordError, OrderingError,
)


def append_to_chain(prev: AuditRecord | None, record: AuditRecord,
                    anchor_hash: str = GENESIS_HASH) -> AuditRecord:
    """Fill ``prev_hash``/``record_hash`` on *record*.

    When appending the first record after a retention prune, ``prev`` is
    ``None`` but the predecessor is the checkpoint anchor rather than
    genesis; callers pass its hash via ``anchor_hash``.
    """
    record.prev_hash = prev.record_hash if prev is not None else anchor_hash
    record.record_hash = payload_hash(record)
    return record


def verify_chain(checkpoint: Checkpoint | None,
                 records: list[AuditRecord]) -> VerifyResult:
    """Verify the whole chain and return a structured, explainable verdict.

    Checks, in order:
      1. non-empty;
      2. sequence numbers are strictly consecutive starting at 1 (or at
         ``checkpoint.seq + 1``) -- detects deletion (gap) and duplicate;
      3. stored order matches seq order -- detects reordering;
      4. each ``record_hash`` recomputes -- detects content modification;
      5. each ``prev_hash`` links to the previous record hash (or to the
         checkpoint anchor) -- detects rewrite/insertion/splice;
      6. the first kept record anchors to the checkpoint when pruned.
    """
    n = len(records)
    if n == 0:
        if checkpoint is not None:
            return VerifyResult(
                ok=True, total=0, first_seq=None, last_seq=None,
                reason="chain_fully_pruned_checkpoint_present")
        return VerifyResult(
            ok=False, error_code=EmptyChainError.code,
            reason="chain is empty (no records and no checkpoint)")

    first_seq = checkpoint.seq + 1 if checkpoint else 1
    last = records[-1]

    def fail(exc_cls, index: int, why: str) -> VerifyResult:
        rec = records[index]
        return VerifyResult(
            ok=False, total=n, first_seq=records[0].seq,
            last_seq=last.seq, error_code=exc_cls.code,
            error_index=index, error_seq=rec.seq, reason=why)

    # 2a. duplicates
    seen: set[int] = set()
    for i, rec in enumerate(records):
        if rec.seq in seen:
            return fail(DuplicateSequenceError, i,
                        f"duplicate sequence number {rec.seq}")
        seen.add(rec.seq)

    # 2b. seq-set completeness: with no checkpoint the chain must cover
    # 1..n contiguously (with a checkpoint: checkpoint.seq+1 .. +n).
    expected_set = set(range(first_seq, first_seq + n))
    if seen != expected_set:
        missing = sorted(expected_set - seen)
        extra = sorted(seen - expected_set)
        first_bad = next(i for i, r in enumerate(records)
                         if r.seq not in expected_set or r.seq != first_seq + i)
        return fail(
            MissingRecordError, first_bad,
            f"sequence set broken: missing={missing} extra={extra} "
            f"(a record was deleted or an out-of-chain record inserted)")

    # 3. reordering: positions must be exactly seq order.
    ordered = sorted(range(n), key=lambda i: records[i].seq)
    if ordered != list(range(n)):
        bad = next(i for i, pos in enumerate(ordered) if pos != i)
        return fail(OrderingError, bad,
                    "record positions do not follow seq order "
                    "(records were reordered)")

    # 6. checkpoint anchor
    anchor_hash = checkpoint.record_hash if checkpoint is not None \
        else GENESIS_HASH
    anchor_seq = checkpoint.seq if checkpoint is not None else 0
    first = records[0]
    if first.prev_hash != anchor_hash:
        return VerifyResult(
            ok=False, total=n, first_seq=first.seq, last_seq=last.seq,
            error_code=CheckpointMismatchError.code
            if checkpoint else ChainBreakError.code,
            error_index=0, error_seq=first.seq,
            reason=(f"first record prev_hash does not match "
                    f"{'checkpoint' if checkpoint else 'genesis'} "
                    f"anchor at seq {anchor_seq}"))

    # 4 + 5. per-record content hash and predecessor link
    for i, rec in enumerate(records):
        recomputed = payload_hash(rec)
        if rec.record_hash != recomputed:
            return fail(
                HashMismatchError, i,
                f"stored record_hash {rec.record_hash[:12]}... != recomputed "
                f"{recomputed[:12]}... (record content was modified)")
        if i == 0:
            expected_prev = anchor_hash
        else:
            expected_prev = records[i - 1].record_hash
        if rec.prev_hash != expected_prev:
            return fail(
                ChainBreakError, i,
                f"prev_hash link broken at seq {rec.seq}: expected "
                f"{expected_prev[:12]}..., got {rec.prev_hash[:12]}... "
                f"(a record was rewritten/inserted)")

    return VerifyResult(
        ok=True, total=n, first_seq=first.seq, last_seq=last.seq,
        reason=f"verified {n} record(s); seq {first.seq}..{last.seq}; "
               f"head {last.record_hash[:12]}...")
