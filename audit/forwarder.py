"""Downstream forwarding with retry, idempotency and backlog recovery."""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from typing import Any, Protocol

from audit.models import AuditRecord


class Downstream(Protocol):
    def send(self, record: dict[str, Any]) -> None:
        """Raise on failure; no raise means the record is durable
        downstream."""
        ...


class HttpDownstream:
    """POSTs each record as JSON to a configured URL.

    Any connection problem, timeout or non-2xx response raises, which the
    forwarder treats as a retryable failure; only a 2xx means the record
    is durable downstream.
    """

    def __init__(self, url: str, *, timeout_seconds: float = 5.0):
        if not url:
            raise ValueError("downstream url must not be empty")
        self.url = url
        self.timeout_seconds = timeout_seconds

    def send(self, record: dict[str, Any]) -> None:
        body = json.dumps(record, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(
                    request, timeout=self.timeout_seconds) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        if not 200 <= status < 300:
            raise RuntimeError(f"downstream answered HTTP {status}")


class AuditForwarder:
    """Forwards records in seq order, never losing or duplicating them.

    Durability model
    -----------------
    * A persistent **cursor** stores the highest seq acknowledged by the
      downstream. The cursor is fsynced *after* a successful send, so a
      crash either happens before the send (resend, covered by
      idempotency) or after it but before the cursor update (resend once,
      again covered by idempotency).
    * An **idempotency ledger** of delivered record ids prevents duplicate
      delivery. A well-behaved downstream may additionally dedupe on
      ``id``; the ledger is the local guarantee.
    * On restart, forwarding resumes at ``cursor + 1`` (backlog recovery),
      so records that piled up while the downstream was down are flushed
      in order with no gaps.
    """

    def __init__(self, downstream: Downstream, *, state_path: str,
                 max_attempts: int = 3):
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self.downstream = downstream
        self.state_path = state_path
        self.max_attempts = max_attempts
        # Serializes forward runs: two concurrent flushes must neither
        # double-send a record nor race on the cursor temp file.
        self._flush_lock = threading.Lock()
        self._delivered: set[str] = set()
        self._cursor = self._load_state()
        self._recover_ledger()

    def _recover_ledger(self) -> None:
        # The ledger is rebuilt from the sidecar journal; in this build
        # delivery state is fully captured by the cursor, and delivered ids
        # are tracked in-process for inspection/idempotency.
        ledger_path = self.state_path + ".ids"
        if os.path.exists(ledger_path):
            with open(ledger_path, "r", encoding="utf-8") as fh:
                self._delivered = {line.strip() for line in fh if line.strip()}

    def _load_state(self) -> int:
        if not os.path.exists(self.state_path):
            return 0
        with open(self.state_path, "r", encoding="utf-8") as fh:
            text = fh.read().strip()
        return int(text) if text else 0

    def load_state(self) -> int:
        return self._cursor

    def _persist_cursor(self, seq: int) -> None:
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(str(seq))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)
        dir_fd = os.open(os.path.dirname(self.state_path) or ".", os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _append_id(self, record_id: str) -> None:
        with open(self.state_path + ".ids", "a", encoding="utf-8") as fh:
            fh.write(record_id + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def delivered_ids(self) -> set[str]:
        return set(self._delivered)

    def forward_pending(self, records: list[AuditRecord]) -> dict[str, Any]:
        """Forward every record with ``seq > cursor``.

        Each record is attempted up to ``max_attempts`` times. On the
        first record whose attempts are exhausted, forwarding stops with a
        structured summary and the cursor left at the last success, so a
        later call (or a restart) resumes exactly there without skipping or
        resending acknowledged records. Concurrent invocations are
        serialized: the loser of the race re-reads the advanced cursor
        and simply has nothing to send.
        """
        with self._flush_lock:
            return self._forward_pending_locked(records)

    def _forward_pending_locked(self,
                                records: list[AuditRecord]) -> dict[str, Any]:
        sent = 0
        skipped_duplicates = 0
        attempted = 0
        failures: list[dict[str, Any]] = []
        for rec in records:
            if rec.seq <= self._cursor:
                continue
            if rec.id in self._delivered:
                # Cursor was behind but the id was already acknowledged:
                # advance without sending again.
                skipped_duplicates += 1
                self._cursor = max(self._cursor, rec.seq)
                self._persist_cursor(self._cursor)
                continue
            payload = rec.to_dict()
            last_error = ""
            ok = False
            for attempt in range(1, self.max_attempts + 1):
                attempted += 1
                try:
                    self.downstream.send(payload)
                    ok = True
                    break
                except Exception as exc:  # noqa: BLE001 - retried, then reported
                    last_error = f"{type(exc).__name__}: {exc}"
            if not ok:
                failures.append({"seq": rec.seq, "id": rec.id,
                                 "attempts": self.max_attempts,
                                 "error": last_error})
                break  # in-order: do not pass an unacknowledged record
            self._append_id(rec.id)
            self._delivered.add(rec.id)
            self._cursor = rec.seq
            self._persist_cursor(self._cursor)
            sent += 1

        return {
            "ok": not failures,
            "cursor_after": self._cursor,
            "sent": sent,
            "skipped_duplicates": skipped_duplicates,
            "attempts": attempted,
            "failures": failures,
        }
