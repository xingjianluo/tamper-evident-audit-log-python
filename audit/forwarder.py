"""Downstream forwarding with retry and backlog recovery.

Delivery semantics (ack-based):

* **No loss**  – the persisted cursor only advances after the downstream
  ``send`` call returns successfully; a failed batch is retried
  (``max_retries`` attempts per flush) and otherwise stays in the backlog
  for the next ``flush``.
* **No duplicates** – the cursor is written atomically (tmp + fsync +
  rename) before the next batch is sent, so a record is handed to the
  downstream at most once per cursor position. Downstreams that can fail
  *after* accepting data should deduplicate on the record ``seq``, which
  is the stable idempotency key.

Recovery: ``flush()`` always resumes from the persisted cursor, so any
backlog accumulated while the downstream was down is drained in order
once it recovers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from .chain import AuditChain

Sender = Callable[[list[dict[str, Any]]], None]


class ForwardError(RuntimeError):
    """A batch could not be delivered within the retry budget."""

    def __init__(self, message: str, delivered: int, pending: int) -> None:
        super().__init__(message)
        self.delivered = delivered
        self.pending = pending


class Forwarder:
    """Cursor-based forwarder: no loss, no duplicates, retry on failure."""

    def __init__(self, chain: AuditChain, send: Sender, batch_size: int = 100,
                 max_retries: int = 3) -> None:
        if batch_size < 1 or max_retries < 1:
            raise ValueError("batch_size and max_retries must be >= 1")
        self.chain = chain
        self.send = send
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.cursor_path = chain.data_dir / "forward_cursor.json"

    # ---- cursor --------------------------------------------------------

    def cursor(self) -> int:
        if self.cursor_path.exists():
            return int(json.loads(self.cursor_path.read_text(encoding="utf-8"))["seq"])
        return 0

    def _save_cursor(self, seq: int) -> None:
        tmp = self.cursor_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"seq": seq}), encoding="utf-8")
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        os.replace(tmp, self.cursor_path)

    def pending(self) -> int:
        cur = self.cursor()
        return sum(1 for r in self.chain.records() if r.seq > cur)

    # ---- delivery ------------------------------------------------------

    @staticmethod
    def _to_envelope(rec) -> dict[str, Any]:
        return {
            "seq": rec.seq, "ts": rec.ts, "actor": rec.actor,
            "action": rec.action, "payload": rec.payload,
            "prev_hash": rec.prev_hash, "hash": rec.hash,
        }

    def flush(self) -> int:
        """Forward pending records in order; returns records delivered.

        Raises ForwardError when a batch exhausts its retries; everything
        delivered so far stays delivered and the remainder stays pending.
        """
        delivered = 0
        while True:
            with self.chain.lock():
                cur = self.cursor()
                batch = [r for r in self.chain.records() if r.seq > cur][: self.batch_size]
            if not batch:
                return delivered
            envelope = [self._to_envelope(r) for r in batch]
            last_exc: Exception | None = None
            for _attempt in range(self.max_retries):
                try:
                    self.send(envelope)
                    last_exc = None
                    break
                except Exception as exc:  # downstream failure -> retry
                    last_exc = exc
            if last_exc is not None:
                raise ForwardError(
                    f"downstream rejected batch seq {batch[0].seq}..{batch[-1].seq} "
                    f"after {self.max_retries} attempt(s): {last_exc}",
                    delivered=delivered, pending=self.pending())
            self._save_cursor(batch[-1].seq)
            delivered += len(batch)
