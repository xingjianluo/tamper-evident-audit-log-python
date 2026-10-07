"""Retention / pruning policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from audit.models import AuditRecord, Checkpoint


def parse_ts(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are treated as UTC."""
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _resolve_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now


def count_expired(records: list[AuditRecord], *, retention_days: int,
                  now: datetime | None = None) -> int:
    """How many of *records* are past the retention window (used to make
    prune results explainable when expired records are held back for
    pending forwarding)."""
    cutoff = _resolve_now(now) - timedelta(days=retention_days)
    return sum(1 for r in records if parse_ts(r.timestamp) < cutoff)


def compute_retained(records: list[AuditRecord], *,
                     retention_days: int,
                     now: datetime | None = None,
                     forwarded_cursor: int | None = None
                     ) -> tuple[Checkpoint | None, list[AuditRecord]]:
    """Decide what survives a retention prune.

    Records older than ``retention_days`` are eligible for removal. Only
    a *contiguous prefix* is removed: pruning stops at the first record
    still within the window, so no in-window record can be deleted and no
    hole can appear. The last removed record becomes the checkpoint
    anchor (its hash keeps the shortened chain verifiable).

    When ``forwarded_cursor`` is given (the highest seq acknowledged by
    the downstream), records with ``seq > forwarded_cursor`` have not
    been handed off yet and are kept *even if expired*; pruning stops at
    the first such record. With ``forwarded_cursor=None`` (forwarding
    disabled) or a cursor that has caught up, behavior is exactly the
    plain time-based rule.

    Returns ``(None, records)`` unchanged when nothing is prunable.
    """
    if retention_days < 0:
        raise ValueError("retention_days must be >= 0")
    if not records:
        return None, records

    cutoff = _resolve_now(now) - timedelta(days=retention_days)

    cut = 0
    for rec in records:
        if forwarded_cursor is not None and rec.seq > forwarded_cursor:
            break  # not delivered downstream yet: keep despite expiry
        if parse_ts(rec.timestamp) < cutoff:
            cut += 1
        else:
            break  # contiguous prefix only

    if cut == 0:
        return None, records

    anchor = records[cut - 1]
    checkpoint = Checkpoint(
        seq=anchor.seq, id=anchor.id, record_hash=anchor.record_hash)
    return checkpoint, records[cut:]
