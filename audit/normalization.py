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

#: Fields accepted on the inbound payload.
_INPUT_FIELDS = frozenset({
    "version", "id", "timestamp", "actor", "action", "resource", "detail",
})
_REQUIRED_FIELDS = ("id", "timestamp", "actor", "action", "resource")

#: Legacy (v0) inbound field names mapped to the canonical names. The
#: legacy generation names the same operation/actor/time/detail
#: differently; every declared legacy field has a canonical home, so no
#: information is lost because of naming.
_LEGACY_FIELD_MAP = {
    "event_id": "id",
    "occurred_at": "timestamp",
    "principal": "actor",
    "operation": "action",
    "object": "resource",
    "attrs": "detail",
}
_LEGACY_INPUT_FIELDS = frozenset(_LEGACY_FIELD_MAP) | {"version"}
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
    """Translate a legacy (v0) payload to canonical field names.

    Unknown legacy fields raise (nothing is silently dropped); missing
    required fields raise naming the *legacy* field so the sender can
    recognize its own schema in the error.
    """
    unknown = set(raw) - _LEGACY_INPUT_FIELDS
    if unknown:
        raise SchemaValidationError(
            f"unknown_field: {sorted(unknown)} (nothing is silently dropped)")
    translated: dict[str, Any] = {}
    for legacy_name, canonical_name in _LEGACY_FIELD_MAP.items():
        if legacy_name in raw:
            translated[canonical_name] = raw[legacy_name]
    # Report missing fields by their *legacy* names so the sender can
    # recognize its own schema in the error.
    legacy_by_canonical = {v: k for k, v in _LEGACY_FIELD_MAP.items()}
    for name in _REQUIRED_FIELDS:
        if name not in translated:
            raise SchemaValidationError(
                f"missing_field: {legacy_by_canonical[name]} "
                f"(legacy v0 name for {name})")
    return translated


def normalize_input(raw: dict[str, Any], *, seq: int,
                    sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS
                    ) -> AuditRecord:
    """Validate + normalize an inbound payload into an AuditRecord.

    Both supported generations (v0 legacy field names, v1 current field
    names) are normalized to the *same* canonical record at
    ``CURRENT_VERSION``; from here on -- hashing, persistence, listing,
    verification -- there is exactly one judgment standard.

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
        version=CURRENT_VERSION,  # normalized: one stored form for all
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
