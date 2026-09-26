"""Append-only hash-chained audit log store.

Each stored record links to the previous one:

    prev_hash(0) = "GENESIS"
    hash(i)      = sha256(prev_hash(i) + "\n" + canonical_json(content_i))

``content`` is the normalized-and-masked record body, so the mask is part
of the integrity guarantee. All mutations are guarded by one re-entrant
lock, so concurrent appends can never produce duplicate/gapped sequence
numbers or torn chain links.

Retention (see retention.py) records an *anchor*: after old records are
purged, ``anchor.json`` names the seq/hash of the last purged record and
verification continues from it, so purging is never reported as tampering.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .models import AuditRecord, FailureReason, VerificationResult
from .normalize import mask_sensitive, normalize_record

GENESIS = "GENESIS"
CANONICAL_KEYS = ("ts", "actor", "action", "payload")


class CorruptLogError(RuntimeError):
    """The on-disk log cannot be parsed at all."""


def _canonical_bytes(body: dict[str, Any]) -> bytes:
    ordered = {k: body[k] for k in CANONICAL_KEYS}
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_hash(prev_hash: str, body: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\n")
    h.update(_canonical_bytes(body))
    return h.hexdigest()


class AuditChain:
    """Append-only, hash-chained, concurrency-safe audit log."""

    def __init__(self, data_dir: Path, sensitive_fields: tuple[str, ...] = ()) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.data_dir / "chain.jsonl"
        self.anchor_path = self.data_dir / "anchor.json"
        self.sensitive_fields = tuple(sensitive_fields)
        # One lock serializes append / verify / purge; the forwarder takes
        # the same lock when snapshotting a batch.
        self._lock = threading.RLock()

    # ---- low level -----------------------------------------------------

    def lock(self) -> threading.RLock:
        return self._lock

    def load_anchor(self) -> tuple[int, str]:
        if self.anchor_path.exists():
            data = json.loads(self.anchor_path.read_text(encoding="utf-8"))
            return int(data["seq"]), str(data["hash"])
        return 0, GENESIS

    def save_anchor(self, seq: int, record_hash: str) -> None:
        tmp = self.anchor_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"seq": seq, "hash": record_hash}, sort_keys=True),
                       encoding="utf-8")
        os.replace(tmp, self.anchor_path)

    def _read_lines(self) -> list[str]:
        if not self.log_path.exists():
            return []
        return [line for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _decode(self, line: str) -> AuditRecord:
        try:
            obj = json.loads(line)
            return AuditRecord(
                seq=int(obj["seq"]), ts=float(obj["ts"]), actor=str(obj["actor"]),
                action=str(obj["action"]), payload=dict(obj["payload"]),
                prev_hash=str(obj["prev_hash"]), hash=str(obj["hash"]),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise CorruptLogError(f"undecodable log line: {exc}") from exc

    def _all_records(self) -> list[AuditRecord]:
        return [self._decode(line) for line in self._read_lines()]

    # ---- public API ----------------------------------------------------

    def append(self, raw: dict[str, Any]) -> AuditRecord:
        """Normalize, mask and append a record; returns the stored record.

        Sequence numbers are assigned under the lock from the on-disk tail,
        so concurrent callers always get distinct consecutive numbers.
        """
        body = normalize_record(raw)  # raises SchemaError before any I/O
        if body["ts"] == 0.0:        # v1 without explicit timestamp
            body["ts"] = time.time()
        body["payload"] = mask_sensitive(body["payload"], self.sensitive_fields)

        with self._lock:
            records = self._all_records()
            anchor_seq, anchor_hash = self.load_anchor()
            if records:
                prev = records[-1].hash
                seq = records[-1].seq + 1
            else:
                prev = anchor_hash
                seq = anchor_seq + 1
            record_hash = compute_hash(prev, body)
            entry = {
                "seq": seq, "ts": body["ts"], "actor": body["actor"],
                "action": body["action"], "payload": body["payload"],
                "prev_hash": prev, "hash": record_hash,
            }
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return AuditRecord(prev_hash=prev, hash=record_hash, seq=seq, **{
                k: body[k] for k in ("ts", "actor", "action", "payload")})

    def records(self) -> list[AuditRecord]:
        """Return all stored (already masked) records in sequence order."""
        with self._lock:
            return self._all_records()

    def verify(self) -> VerificationResult:
        """Replay the whole chain and return a distinguishable verdict.

        Per record, in precedence order:

        * undecodable line            -> SCHEMA_ERROR
        * ``seq < expected``          -> SEQ_DUPLICATE (copied/replayed)
        * ``prev_hash`` mismatch      -> SEQ_REORDERED if the expected seq
          appears later in the file, else SEQ_MISSING (deleted)
        * ``seq > expected``          -> SEQ_MISSING (records deleted)
        * recomputed hash mismatch    -> HASH_MISMATCH (content modified)

        The reorder-vs-delete distinction is the reason this reads the
        whole file before walking it.
        """
        with self._lock:
            expected_seq, expected_prev = self.load_anchor()
            expected_seq += 1
            checked = 0
            records: list[AuditRecord] = []
            for line in self._read_lines():
                try:
                    records.append(self._decode(line))
                except CorruptLogError as exc:
                    return VerificationResult(False, checked, FailureReason.SCHEMA_ERROR,
                                              f"record cannot be parsed: {exc}")
            later_seqs = [r.seq for r in records]
            for idx, rec in enumerate(records):
                checked += 1
                if rec.seq < expected_seq:
                    return VerificationResult(False, checked, FailureReason.SEQ_DUPLICATE,
                                              f"seq {rec.seq} repeats (expected {expected_seq})",
                                              rec.seq)
                if rec.prev_hash != expected_prev or rec.seq > expected_seq:
                    if expected_seq in later_seqs[idx + 1:]:
                        return VerificationResult(
                            False, checked, FailureReason.SEQ_REORDERED,
                            f"expected seq {expected_seq} at position {idx}, "
                            f"but it appears later (records were reordered)", rec.seq)
                    return VerificationResult(
                        False, checked, FailureReason.SEQ_MISSING,
                        f"expected seq {expected_seq} is absent from the log "
                        f"(record(s) deleted)", rec.seq)
                body = {k: getattr(rec, k) for k in CANONICAL_KEYS}
                if compute_hash(expected_prev, body) != rec.hash:
                    return VerificationResult(False, checked, FailureReason.HASH_MISMATCH,
                                              f"seq {rec.seq} content hash differs; "
                                              f"the record was modified", rec.seq)
                expected_seq = rec.seq + 1
                expected_prev = rec.hash
            return VerificationResult(True, checked, FailureReason.OK,
                                      f"{checked} record(s) verified, chain intact")
