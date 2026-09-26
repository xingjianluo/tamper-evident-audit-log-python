"""Domain error types.

Each integrity failure has a *distinct* error type / code so that the
final verdict is explainable (tamper vs. missing vs. duplicate vs.
schema problem vs. chain break).
"""


class AuditError(Exception):
    """Base class for all audit-domain errors."""

    code = "audit_error"


class SchemaValidationError(AuditError):
    """Record payload fails schema/version rules (unknown/missing/illegal)."""

    code = "schema_validation_error"


class SequenceConflictError(AuditError):
    """Concurrent append produced a duplicate sequence number."""

    code = "sequence_conflict"


class IntegrityError(AuditError):
    """Base class for verification failures."""

    code = "integrity_error"

    def __init__(self, message: str, *, index: int | None = None,
                 seq: int | None = None, reason: str = ""):
        super().__init__(message)
        self.index = index
        self.seq = seq
        self.reason = reason or self.code


class EmptyChainError(IntegrityError):
    code = "empty_chain"


class MissingRecordError(IntegrityError):
    """A record was deleted / a sequence number is missing."""

    code = "missing_record"


class DuplicateSequenceError(IntegrityError):
    """Two records share the same sequence number."""

    code = "duplicate_sequence"


class OrderingError(IntegrityError):
    """Records appear in a different order than their sequence numbers."""

    code = "ordering_error"


class HashMismatchError(IntegrityError):
    """Stored record hash differs from the recomputed hash (content tampered)."""

    code = "hash_mismatch"


class ChainBreakError(IntegrityError):
    """prev_hash link does not match the previous record (rewrite/insert)."""

    code = "chain_break"


class CheckpointMismatchError(IntegrityError):
    """Checkpoint anchor does not match the first kept record."""

    code = "checkpoint_mismatch"


class RetentionError(AuditError):
    code = "retention_error"


class ForwardError(AuditError):
    code = "forward_error"
