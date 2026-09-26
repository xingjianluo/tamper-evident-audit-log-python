"""Tamper-evident audit log package."""

from audit.service import AuditService, get_audit_service

__all__ = ["AuditService", "get_audit_service"]
