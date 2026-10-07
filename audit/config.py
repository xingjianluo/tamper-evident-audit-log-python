"""Service configuration, sourced from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

from audit.normalization import DEFAULT_SENSITIVE_KEYS


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: str = "data"
    retention_days: int = 90
    forward_enabled: bool = False
    forward_url: str = ""
    forward_state_file: str = "forward.state"
    max_forward_attempts: int = 3
    forward_timeout_seconds: float = 5.0
    sensitive_keys: frozenset[str] = frozenset(DEFAULT_SENSITIVE_KEYS)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"environment variable {name} must be an integer, "
                         f"got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"environment variable {name} must be a number, "
                         f"got {raw!r}") from exc


def load_settings() -> Settings:
    """Load settings from AUDIT_* environment variables."""
    extra = os.environ.get("AUDIT_SENSITIVE_KEYS", "").strip()
    keys = set(DEFAULT_SENSITIVE_KEYS)
    if extra:
        keys.update(k.strip().lower() for k in extra.split(",") if k.strip())
    return Settings(
        data_dir=os.environ.get("AUDIT_DATA_DIR", "data"),
        retention_days=_env_int("AUDIT_RETENTION_DAYS", 90),
        forward_enabled=_env_bool("AUDIT_FORWARD_ENABLED", False),
        forward_url=os.environ.get("AUDIT_FORWARD_URL", "").strip(),
        forward_state_file=os.environ.get("AUDIT_FORWARD_STATE",
                                          "forward.state"),
        max_forward_attempts=_env_int("AUDIT_FORWARD_MAX_ATTEMPTS", 3),
        forward_timeout_seconds=_env_float("AUDIT_FORWARD_TIMEOUT", 5.0),
        sensitive_keys=frozenset(keys),
    )
