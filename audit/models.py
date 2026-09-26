"""Record model and verification result types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class FailureReason(Enum):
    """Distinguishable integrity failure reasons."""

    OK = "ok"
    SCHEMA_ERROR = "schema_error"          # record cannot be parsed/normalized
    SEQ_MISSING = "seq_missing"            # expected seq absent => record deleted
    SEQ_REORDERED = "seq_reordered"        # expected seq found later => reordered
    SEQ_DUPLICATE = "seq_duplicate"        # a record was copied/replayed
    HASH_MISMATCH = "hash_mismatch"        # record content was modified


@dataclass
class AuditRecord:
    seq: int
    ts: float
    actor: str
    action: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str


@dataclass
class VerificationResult:
    ok: bool
    checked: int
    reason: FailureReason = FailureReason.OK
    detail: str = ""
    seq: int | None = None
