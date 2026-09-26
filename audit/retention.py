"""Retention policy.

Expired records are purged as a contiguous prefix only, and a hash
*anchor* is persisted (seq + hash of the last purged record). Verification
then starts at that anchor, so lawful purging is never mistaken for
tampering, while any modification/deletion *after* the anchor is still
detected.

Loss safety: records that are still in the forwarding backlog
(``seq > safe_seq``) are never purged, even if their TTL already elapsed.
Purge takes the chain lock for its whole critical section: concurrent
appends are serialized against the file rewrite and can therefore never
be deleted by a purge that started before them.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .chain import AuditChain

_DAY_SECONDS = 86400


def purge_expired(chain: AuditChain, retention_days: int, now: float | None = None,
                  safe_seq: int | None = None) -> int:
    """Purge records older than ``retention_days``; returns number purged.

    ``safe_seq`` is the highest seq that downstream forwarding has
    acknowledged (defaults to the current anchor); newer expired records
    are retained until forwarded, guaranteeing no record loss.
    """
    if retention_days < 0:
        raise ValueError("retention_days must be >= 0")
    cutoff = (time.time() if now is None else now) - retention_days * _DAY_SECONDS

    with chain.lock():
        records = chain.records()  # already under the re-entrant lock
        anchor_seq, _ = chain.load_anchor()
        if safe_seq is None:
            safe_seq = anchor_seq

        # Largest k such that the prefix [0:k] is fully expired AND
        # k <= number of records acknowledged as forwarded.
        k = 0
        for rec in records:
            if rec.ts < cutoff and rec.seq <= safe_seq:
                k += 1
            else:
                break
        if k == 0:
            return 0

        last_purged = records[k - 1]
        tmp = chain.log_path.with_suffix(".jsonl.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for rec in records[k:]:
                f.write(json.dumps({
                    "seq": rec.seq, "ts": rec.ts, "actor": rec.actor,
                    "action": rec.action, "payload": rec.payload,
                    "prev_hash": rec.prev_hash, "hash": rec.hash,
                }, sort_keys=True, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        # Anchor first, then swap. If the process dies between the two,
        # worst case verification merely re-checks old records from the new
        # anchor; both files still contain mutually consistent data.
        chain.save_anchor(last_purged.seq, last_purged.hash)
        os.replace(tmp, chain.log_path)
        return k
