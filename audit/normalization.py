"""Version-aware normalization, schema validation and masking."""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any

from audit.models import (
    CURRENT_VERSION, LEGACY_VERSION, SUPPORTED_VERSIONS, AuditRecord,
)
from audit.errors import SchemaValidationError

#: Sensitive keys are masked before hashing/persistence.
DEFAULT_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "id_card", "idcard", "phone", "email",
    "bank_card", "card_number", "ssn",
})

#: Marker placed in lieu of a sensitive value. It carries no information
#: about the original, so the secret itself can never reach disk or a
#: response.
MASK_TOKEN = "__redacted__"

#: Fields accepted on the inbound payload (current version).
_INPUT_FIELDS = frozenset({
    "version", "id", "timestamp", "actor", "action", "resource", "detail",
})
_REQUIRED_FIELDS = ("id", "timestamp", "actor", "action", "resource")
#: Legacy (v0) field names mapped onto the canonical names. The legacy
#: payload expresses the same operation/actor/time/detail with different
#: key names; every canonical field has exactly one legacy source, so
#: normalization loses nothing and invents nothing.
_LEGACY_FIELD_MAP = {
    "event_id": "id",
    "at": "timestamp",
    "user": "actor",
    "op": "action",
    "target": "resource",
    "meta": "detail",
}
_LEGACY_INPUT_FIELDS = frozenset({"version", *_LEGACY_FIELD_MAP})
#: Fields accepted on a persisted record.
_STORED_FIELDS = frozenset({
    "version", "seq", "id", "timestamp", "actor", "action", "resource",
    "detail", "prev_hash", "record_hash",
})

_KEY_SPLIT_RE = re.compile(r"[.\-]")


def _is_sensitive_key(key: str, sensitive_keys: frozenset[str]) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in sensitive_keys:
        return True
    # Suffix match so nested keys like ``user.password`` are caught.
    last = _KEY_SPLIT_RE.split(normalized)[-1]
    return last in sensitive_keys


def mask_sensitive(value: Any,
                   sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS,
                   *, _key: str = "") -> Any:
    """Recursively mask sensitive keys; the raw secret never survives."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise SchemaValidationError(
                    f"illegal_value: non-string object key {k!r}")
            if _is_sensitive_key(k, sensitive_keys):
                out[k] = MASK_TOKEN
            else:
                out[k] = mask_sensitive(v, sensitive_keys, _key=k)
        return out
    if isinstance(value, list):
        return [mask_sensitive(v, sensitive_keys, _key=_key) for v in value]
    return value


def _validate_json_native(value: Any, path: str) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SchemaValidationError(
                f"illegal_value: non-finite number at {path}")
        return
    if isinstance(value, (dict, list)):
        nodes: list[tuple[Any, str]] = [(value, path)]
        while nodes:
            cur, p = nodes.pop()
            if isinstance(cur, dict):
                for k, v in cur.items():
                    if not isinstance(k, str):
                        raise SchemaValidationError(
                            f"illegal_value: non-string key at {p}")
                    nodes.append((v, f"{p}.{k}"))
            elif isinstance(cur, list):
                for i, v in enumerate(cur):
                    nodes.append((v, f"{p}[{i}]"))
            else:
                _validate_json_native(cur, p)
        return
    raise SchemaValidationError(
        f"illegal_value: {type(value).__name__} at {path} is not JSON-native")


def _require_nonempty_str(raw: dict[str, Any], name: str) -> str:
    if name not in raw:
        raise SchemaValidationError(f"missing_field: {name}")
    value = raw[name]
    if not isinstance(value, str) or isinstance(value, bool):
        raise SchemaValidationError(
            f"illegal_value: {name} must be a string")
    if not value.strip():
        raise SchemaValidationError(f"illegal_value: {name} must not be empty")
    return value


def _translate_legacy(raw: dict[str, Any]) -> dict[str, Any]:
    """Map a legacy (v0) payload onto canonical field names.

    Unknown legacy fields raise (nothing is silently dropped); the
    canonical field names are *not* accepted on a v0 payload, so a
    mixed-generation payload is rejected rather than half-translated.
    """
    unknown = set(raw) - _LEGACY_INPUT_FIELDS
    if unknown:
        raise SchemaValidationError(
            f"unknown_field: {sorted(unknown)} on a v{LEGACY_VERSION} payload "
            f"(nothing is silently dropped)")
    translated: dict[str, Any] = {}
    for legacy_name, canonical_name in _LEGACY_FIELD_MAP.items():
        if legacy_name in raw:
            translated[canonical_name] = raw[legacy_name]
    return translated


def normalize_input(raw: dict[str, Any], *, seq: int,
                    sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS
                    ) -> AuditRecord:
    """Validate + normalize an inbound payload into an AuditRecord.

    Both supported generations (legacy v0 field names, current v1) are
    normalized onto the *same* canonical semantics before chaining, so
    downstream masking, persistence, listing and verification apply one
    uniform standard regardless of the source generation.

    Unknown fields raise. Missing required fields raise. Illegal values
    raise. Nothing is silently dropped or filled. Sensitive values are
    masked *before* hashing, so on-disk/API records never carry secrets.
    """
    if not isinstance(raw, dict):
        raise SchemaValidationError("illegal_value: payload must be an object")

    version = raw.get("version", CURRENT_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        raise SchemaValidationError("illegal_value: version must be an integer")
    if version not in SUPPORTED_VERSIONS:
        raise SchemaValidationError(
            f"unsupported_version: {version} "
            f"(supported: {sorted(SUPPORTED_VERSIONS)})")

    if version == LEGACY_VERSION:
        raw = _translate_legacy(raw)
    else:
        unknown = set(raw) - _INPUT_FIELDS
        if unknown:
            raise SchemaValidationError(
                f"unknown_field: {sorted(unknown)} "
                f"(nothing is silently dropped)")

    rec_id = _require_nonempty_str(raw, "id")
    actor = _require_nonempty_str(raw, "actor")
    action = _require_nonempty_str(raw, "action")
    resource = _require_nonempty_str(raw, "resource")

    timestamp = _require_nonempty_str(raw, "timestamp")
    try:
        datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise SchemaValidationError(
            f"illegal_value: timestamp is not ISO-8601: {timestamp!r}") from exc

    detail = raw.get("detail", {})
    if not isinstance(detail, dict):
        raise SchemaValidationError("illegal_value: detail must be an object")
    _validate_json_native(detail, "detail")
    masked_detail = mask_sensitive(detail, sensitive_keys)

    return AuditRecord(
        version=version,
        seq=seq,
        id=rec_id,
        timestamp=timestamp,
        actor=actor,
        action=action,
        resource=resource,
        detail=masked_detail,
        prev_hash="",
        record_hash="",
    )


def canonicalize_stored(raw: dict[str, Any]) -> AuditRecord:
    """Turn a persisted record dict back into an AuditRecord."""
    if not isinstance(raw, dict):
        raise SchemaValidationError("corrupt_record: stored line is not object")
    unknown = set(raw) - _STORED_FIELDS
    if unknown:
        raise SchemaValidationError(
            f"corrupt_record: unknown stored fields {sorted(unknown)}")
    missing = [name for name in (
        "version", "seq", "id", "timestamp", "actor", "action", "resource",
        "detail", "prev_hash", "record_hash") if name not in raw]
    if missing:
        raise SchemaValidationError(
            f"corrupt_record: missing stored fields {missing}")
    if not isinstance(raw["seq"], int) or isinstance(raw["seq"], bool):
        raise SchemaValidationError("corrupt_record: seq must be integer")
    for name in ("id", "timestamp", "actor", "action", "resource",
                 "prev_hash", "record_hash"):
        if not isinstance(raw[name], str):
            raise SchemaValidationError(
                f"corrupt_record: {name} must be a string")
    if not isinstance(raw["detail"], dict):
        raise SchemaValidationError("corrupt_record: detail must be object")
    if not isinstance(raw["version"], int) or isinstance(raw["version"], bool):
        raise SchemaValidationError("corrupt_record: version must be integer")
    return AuditRecord(
        version=raw["version"], seq=raw["seq"], id=raw["id"],
        timestamp=raw["timestamp"], actor=raw["actor"], action=raw["action"],
        resource=raw["resource"], detail=raw["detail"],
        prev_hash=raw["prev_hash"], record_hash=raw["record_hash"],
    )
