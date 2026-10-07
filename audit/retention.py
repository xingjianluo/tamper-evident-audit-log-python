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


def compute_retained(records: list[AuditRecord], *,
                     retention_days: int,
                     now: datetime | None = None,
                     forwarded_through: int | None = None
                     ) -> tuple[Checkpoint | None, list[AuditRecord]]:
    """Decide what survives a retention prune.

    Records older than ``retention_days`` are eligible for removal — but
    only once the downstream has acknowledged them: when
    ``forwarded_through`` (the durable forwarding cursor) is given, any
    record with ``seq > forwarded_through`` is kept even if expired, so an
    overdue record can never be deleted before it was delivered. When
    forwarding is disabled (``forwarded_through is None``) or the cursor
    has caught up, the rule degenerates to the pure time-based policy.

    Only a *contiguous prefix* is removed: pruning stops at the first
    record that is in-window or not yet forwarded, so no in-use record
    can be deleted and no hole can appear. The last removed record
    becomes the checkpoint anchor (its hash keeps the shortened chain
    verifiable).

    Returns ``(None, records)`` unchanged when nothing is prunable.
    """
    if retention_days < 0:
        raise ValueError("retention_days must be >= 0")
    if forwarded_through is not None and forwarded_through < 0:
        raise ValueError("forwarded_through must be >= 0")
    if not records:
        return None, records

    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    cutoff = now - timedelta(days=retention_days)

    cut = 0
    for rec in records:
        expired = parse_ts(rec.timestamp) < cutoff
        delivered = forwarded_through is None or rec.seq <= forwarded_through
        if expired and delivered:
            cut += 1
        else:
            break  # contiguous prefix only

    if cut == 0:
        return None, records

    anchor = records[cut - 1]
    checkpoint = Checkpoint(
        seq=anchor.seq, id=anchor.id, record_hash=anchor.record_hash)
    return checkpoint, records[cut:]
