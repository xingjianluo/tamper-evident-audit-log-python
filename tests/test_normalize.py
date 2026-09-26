"""Schema version normalization, strict validation and masking."""

from __future__ import annotations

import pytest

from audit.normalize import SchemaError, mask_sensitive, normalize_record
from tests._case_log import log_case


def test_v1_and_v2_normalize_to_same_shape():
    v1 = {"actor": "u", "action": "a", "payload": {"k": 1}, "ts": 10}
    v2 = {"version": "v2", "timestamp": 10, "actor": "u", "action": "a", "payload": {"k": 1}}
    n1, n2 = normalize_record(v1), normalize_record(v2)
    log_case("normalize-versions", {"v1": v1, "v2": v2},
             "both map to {ts,actor,action,payload}", f"equal={n1 == n2}")
    assert n1 == n2 == {"ts": 10.0, "actor": "u", "action": "a", "payload": {"k": 1}}


@pytest.mark.parametrize("raw,kind", [
    ({"actor": "u", "action": "a", "payload": {}, "extra": 1}, "unknown_field"),
    ({"action": "a", "payload": {}}, "missing_field"),
    ({"version": "v9", "actor": "u", "action": "a", "payload": {}}, "illegal_value"),
    ({"actor": " ", "action": "a", "payload": {}}, "illegal_value"),
    ({"actor": "u", "action": "a", "payload": {"k": {1, 2}}}, "illegal_value"),
    ({"actor": "u", "action": "a", "payload": {}, "ts": -1}, "illegal_value"),
])
def test_bad_records_are_rejected(raw, kind):
    with pytest.raises(SchemaError) as exc:
        normalize_record(raw)
    log_case("normalize-reject", raw, f"rejected with kind={exc.value.kind}", "PASS: loud rejection")
    assert exc.value.kind == kind


def test_masking_is_deep_and_non_destructive():
    payload = {"token": "raw", "nested": [{"secret": "s", "ok": 1}], "keep": 2}
    original = __import__("copy").deepcopy(payload)
    masked = mask_sensitive(payload, ("token", "secret"))
    log_case("mask", original,
             "keys named token/secret replaced recursively; input untouched",
             masked)
    assert masked == {"token": "***REDACTED***",
                      "nested": [{"secret": "***REDACTED***", "ok": 1}], "keep": 2}
    assert payload == original  # raw value never mutated
