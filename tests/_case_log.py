"""Small helper so every test logs: input -> evidence -> conclusion."""

from __future__ import annotations

from audit.models import VerificationResult


def log_case(case_id: str, given: object, basis: object, conclusion: object) -> None:
    print(f"\n[CASE {case_id}]\n  输入(input)     : {given}\n"
          f"  判定依据(basis) : {basis}\n  结论(conclusion): {conclusion}")


def verdict_text(result: VerificationResult) -> str:
    return (f"ok={result.ok}, checked={result.checked}, "
            f"reason={result.reason.value}, seq={result.seq}, detail={result.detail}")
