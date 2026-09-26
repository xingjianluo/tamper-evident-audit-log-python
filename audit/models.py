"""Canonical record model (version-aware normalization happens here)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

#: Current record format version handled by this build.
CURRENT_VERSION = 1
#: Set of versions we know how to normalize.
SUPPORTED_VERSIONS = frozenset({1})

#: Fields that make up the canonical (hash-covered) payload.
CANONICAL_FIELDS = ("version", "seq", "id", "timestamp", "actor",
                    "action", "resource", "detail", "prev_hash")


@dataclass(slots=True)
class AuditRecord:
    """One immutable audit record.

    ``record_hash`` covers every canonical field (incl. ``prev_hash``);
    it is therefore *not* itself part of the hashed payload.
    """

    version: int
    seq: int
    id: str
    timestamp: str
    actor: str
    action: str
    resource: str
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    record_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Checkpoint:
    """Anchor written after a retention prune, so the shortened chain
    still has a verifiable predecessor."""

    seq: int
    id: str
    record_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class VerifyResult:
    ok: bool
    total: int = 0
    first_seq: int | None = None
    last_seq: int | None = None
    error_code: str = ""
    error_index: int | None = None
    error_seq: int | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
