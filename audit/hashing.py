"""Hashing primitives for the hash chain."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from audit.models import CANONICAL_FIELDS, AuditRecord

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization.

    Keys are sorted recursively and no insignificant whitespace is
    emitted, so the same logical record always yields the same bytes
    regardless of dict insertion order or JSON formatting.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def payload_hash(record: AuditRecord) -> str:
    """SHA-256 over the canonical fields of a record.

    ``record_hash`` is excluded (it is the output); ``prev_hash`` is
    included, so the hash both commits to the record content and to its
    position/successor link in the chain.
    """
    payload = {name: getattr(record, name) for name in CANONICAL_FIELDS}
    return hashlib.sha256(canonical_json(payload)).hexdigest()
