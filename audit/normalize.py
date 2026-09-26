"""Schema normalization and sensitive-field masking.

Two input schema versions are accepted and normalized to one canonical form:

* v1 (implicit): {"actor", "action", "payload", "ts"?}
* v2: {"version": "v2", "timestamp", "actor", "action", "payload"}

Unknown top-level fields, missing required fields and illegal values are
*rejected loudly* (SchemaError), never silently dropped or default-filled.
Masking happens before hashing, so stored/hashed content only ever contains
the masked value; the original sensitive value never touches disk or API
responses.
"""

from __future__ import annotations

from typing import Any

# Fixed public marker. It carries no information about the original value.
MASK_MARKER = "***REDACTED***"

_V1_KEYS = frozenset({"actor", "action", "payload", "ts"})
_V2_KEYS = frozenset({"version", "timestamp", "actor", "action", "payload"})
_CANON_KEYS = ("ts", "actor", "action", "payload")


class SchemaError(ValueError):
    """Raised when a raw record cannot be normalized.

    Coarse classification lives in ``kind`` so callers can explain *why*
    normalization failed: unknown_field / missing_field / illegal_value.
    """

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def _require_str(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise SchemaError("illegal_value", f"field {name!r} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise SchemaError("illegal_value", f"field {name!r} must not be empty")
    return value


def _require_jsonish(value: Any, path: str) -> None:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise SchemaError("illegal_value", f"{path}: object keys must be strings")
            _require_jsonish(v, f"{path}.{k}")
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            _require_jsonish(v, f"{path}[{i}]")
        return
    raise SchemaError("illegal_value", f"{path}: unsupported value type {type(value).__name__}")


def normalize_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw record of any supported version into canonical form.

    Canonical form: {"ts": float, "actor": str, "action": str,
    "payload": dict[str, JSON]} with keys in a fixed order.
    Raises SchemaError on unknown fields, missing fields or illegal values.
    """
    if not isinstance(raw, dict):
        raise SchemaError("illegal_value", f"record must be an object, got {type(raw).__name__}")

    version = raw.get("version", "v1")
    if version == "v2":
        unknown = set(raw) - _V2_KEYS
        if unknown:
            raise SchemaError("unknown_field", f"v2 record has unknown field(s): {sorted(unknown)}")
        for name in ("timestamp", "actor", "action", "payload"):
            if name not in raw:
                raise SchemaError("missing_field", f"v2 record is missing required field {name!r}")
        ts = raw["timestamp"]
        actor = raw["actor"]
        action = raw["action"]
        payload = raw["payload"]
    elif version == "v1":
        unknown = set(raw) - _V1_KEYS
        if unknown:
            raise SchemaError("unknown_field", f"v1 record has unknown field(s): {sorted(unknown)}")
        for name in ("actor", "action", "payload"):
            if name not in raw:
                raise SchemaError("missing_field", f"v1 record is missing required field {name!r}")
        ts = raw.get("ts", 0)
        actor = raw["actor"]
        action = raw["action"]
        payload = raw["payload"]
    else:
        raise SchemaError("illegal_value", f"unsupported schema version {version!r}")

    # ts: int/float but not bool; must be a plausible non-negative epoch.
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or isinstance(ts, float) and (ts != ts):
        raise SchemaError("illegal_value", "field 'ts'/'timestamp' must be a finite number")
    if ts < 0:
        raise SchemaError("illegal_value", "field 'ts'/'timestamp' must not be negative")

    actor = _require_str("actor", actor)
    action = _require_str("action", action)
    if not isinstance(payload, dict):
        raise SchemaError("illegal_value", f"field 'payload' must be an object, got {type(payload).__name__}")
    _require_jsonish(payload, "payload")

    return {"ts": float(ts), "actor": actor, "action": action, "payload": dict(payload)}


def _mask_in_place(value: Any, sensitive: set[str]) -> Any:
    if isinstance(value, dict):
        return {k: (MASK_MARKER if k in sensitive else _mask_in_place(v, sensitive))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_in_place(v, sensitive) for v in value]
    return value


def mask_sensitive(payload: dict[str, Any], sensitive_fields: tuple[str, ...]) -> dict[str, Any]:
    """Return a deep copy of payload with sensitive leaf fields masked.

    Matching is by key name at every nesting level. The original payload
    object is never mutated or returned, so raw secrets cannot leak.
    """
    return _mask_in_place(payload, set(sensitive_fields))
