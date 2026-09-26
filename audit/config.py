"""Configuration for the audit chain, retention and forwarding."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AuditConfig:
    """Runtime configuration for the audit subsystem."""

    data_dir: Path = Path("data")
    retention_days: int = 30
    sensitive_fields: tuple[str, ...] = ("password", "token", "secret", "id_card")
    forward_url: str | None = None
    forward_batch_size: int = 100
    forward_max_retries: int = 3
