"""Application facade: ties storage, integrity, retention and forwarding
into one concurrency-safe service."""

from __future__ import annotations

import os
import threading
from typing import Any

from audit.config import Settings, load_settings
from audit.errors import IntegrityError, SequenceConflictError
from audit.forwarder import AuditForwarder, Downstream
from audit.hashing import GENESIS_HASH
from audit.integrity import append_to_chain, verify_chain
from audit.models import VerifyResult
from audit.normalization import normalize_input
from audit.retention import compute_retained
from audit.storage import Storage


class AuditService:
    """Thread-safe entry point used by the HTTP API and tests.

    Concurrency model: every mutating/reading operation that depends on a
    consistent chain snapshot runs inside ``storage.locked()`` (in-process
    + cross-process). Sequence numbers are assigned under that lock, so
    concurrent appends can neither duplicate a seq nor interleave a
    half-built link.
    """

    def __init__(self, settings: Settings | None = None,
                 downstream: Downstream | None = None):
        self.settings = settings or load_settings()
        self.storage = Storage(self.settings.data_dir)
        self._downstream = downstream
        self._forwarder: AuditForwarder | None = None
        if self.settings.forward_enabled and downstream is not None:
            state_path = os.path.join(self.settings.data_dir,
                                      self.settings.forward_state_file)
            self._forwarder = AuditForwarder(
                downstream, state_path=state_path,
                max_attempts=self.settings.max_forward_attempts)

    # ------------------------------------------------------------------ #
    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate, mask, link and durably persist one record."""
        with self.storage.locked():
            checkpoint, records = self.storage.load_all()
            next_seq = (records[-1].seq + 1) if records else (
                checkpoint.seq + 1 if checkpoint else 1)

            record = normalize_input(
                payload, seq=next_seq,
                sensitive_keys=self.settings.sensitive_keys)
            prev = records[-1] if records else None
            anchor = checkpoint.record_hash if (
                prev is None and checkpoint is not None) else None
            append_to_chain(prev, record,
                            anchor if anchor is not None else GENESIS_HASH)

            # Defensive: the freshly assigned seq must be unique.
            if any(r.seq == record.seq for r in records):
                raise SequenceConflictError(
                    f"duplicate sequence {record.seq} under concurrent append")

            self.storage.append(record)
        return record.to_dict()

    def list_records(self) -> list[dict[str, Any]]:
        """Return records for external responses.

        Masked values were already replaced before persistence, so no raw
        sensitive content can appear here.
        """
        with self.storage.locked():
            _cp, records = self.storage.load_all()
            return [r.to_dict() for r in records]

    def verify(self) -> VerifyResult:
        with self.storage.locked():
            checkpoint, records = self.storage.load_all()
            return verify_chain(checkpoint, records)

    def prune(self, *, now=None) -> dict[str, Any]:
        """Apply the retention policy under the append lock.

        The retained set is computed from the snapshot taken *inside* the
        lock and rewritten atomically; any append during the operation
        blocks on the same lock first, so new writes are never deleted.
        """
        with self.storage.locked():
            checkpoint, records = self.storage.load_all()
            new_cp, retained = compute_retained(
                records, retention_days=self.settings.retention_days, now=now)
            if new_cp is None:
                return {"pruned": 0, "kept": len(records), "rewritten": False}
            pruned = len(records) - len(retained)
            self.storage.rewrite(new_cp, retained)
            verdict = verify_chain(new_cp, retained)
            if not verdict.ok:
                # Should be impossible given the prefix rule; fail loudly
                # rather than silently leave an unverifiable chain.
                raise IntegrityError(
                    f"post-prune verification failed: {verdict.reason}")
            return {"pruned": pruned, "kept": len(retained),
                    "rewritten": True, "checkpoint_seq": new_cp.seq,
                    "verify": verdict.to_dict()}

    def forward(self) -> dict[str, Any]:
        """Flush pending records to the downstream (no loss / no dup)."""
        if self._forwarder is None:
            return {"ok": False, "enabled": False,
                    "reason": "forwarding_disabled"}
        with self.storage.locked():
            _cp, records = self.storage.load_all()
        return {"enabled": True, **self._forwarder.forward_pending(records)}


_service: AuditService | None = None
_service_lock = threading.Lock()


def get_audit_service() -> AuditService:
    """Process-wide singleton used by the FastAPI handlers."""
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = AuditService()
    return _service
