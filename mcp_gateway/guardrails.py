"""Per-tool guardrails: payload limits, argument allow-lists, deny predicates,
and PII scrubbing on outputs.

Input checks run before the tool; the scrub runs on whatever the tool
returned. A denial raises ``GuardrailDenied`` (-32001), which the gateway
audits with the reason and returns to the client without the payload.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from pydantic import BaseModel

from .protocol import GUARDRAIL_DENIED, GatewayError

DenyPredicate = Callable[[dict[str, Any], Any], str | None]


class GuardrailDenied(GatewayError):
    code = GUARDRAIL_DENIED


@dataclass(frozen=True)
class ToolPolicy:
    """What a single tool is allowed to receive and emit.

    ``deny_if(arguments, principal)`` returns a reason string to deny, or
    ``None`` to allow; it runs after the size and allow-list checks.
    """

    max_payload_bytes: int = 64 * 1024
    allowed_args: frozenset[str] | None = None
    scrub_output: bool = True
    deny_if: DenyPredicate | None = None

    def with_allowed_args(self, *names: str) -> ToolPolicy:
        return ToolPolicy(
            max_payload_bytes=self.max_payload_bytes,
            allowed_args=frozenset(names),
            scrub_output=self.scrub_output,
            deny_if=self.deny_if,
        )


DEFAULT_POLICY = ToolPolicy()


def payload_size(arguments: Any) -> int:
    return len(
        json.dumps(arguments, separators=(",", ":"), ensure_ascii=False, default=str).encode()
    )


def check_input(policy: ToolPolicy, tool: str, arguments: dict[str, Any], principal: Any) -> None:
    """Apply the policy's input checks; raise ``GuardrailDenied`` on the first failure."""
    size = payload_size(arguments)
    if size > policy.max_payload_bytes:
        raise GuardrailDenied(
            f"payload of {size} bytes exceeds limit of {policy.max_payload_bytes} for '{tool}'",
            data={"reason": "payload_too_large", "tool": tool, "size": size},
        )
    if policy.allowed_args is not None:
        unknown = sorted(set(arguments) - policy.allowed_args)
        if unknown:
            raise GuardrailDenied(
                f"arguments not allowed for '{tool}': {', '.join(unknown)}",
                data={"reason": "argument_not_allowed", "tool": tool, "arguments": unknown},
            )
    if policy.deny_if is not None:
        reason = policy.deny_if(arguments, principal)
        if reason:
            raise GuardrailDenied(
                f"denied by policy for '{tool}': {reason}",
                data={"reason": "deny_if", "tool": tool, "detail": reason},
            )


# --- PII scrubbing ---------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SA_ID_RE = re.compile(r"(?<!\d)\d{13}(?!\d)")
# Candidate phone: optional +CC, optional (0), then 9-10 digits in 2/3/4 groups.
PHONE_RE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[ -]?)?(?:\(0\)[ -]?|0)?\d{2}[ -]?\d{3}[ -]?\d{4}(?![\w-])"
)

EMAIL_TOKEN = "[EMAIL]"
PHONE_TOKEN = "[PHONE]"
SA_ID_TOKEN = "[SA_ID]"


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def sa_id_valid(candidate: str) -> bool:
    """13-digit South African ID: YYMMDD SSSS C A Z with a Luhn check digit."""
    if len(candidate) != 13 or not candidate.isdigit():
        return False
    yy, mm, dd = int(candidate[0:2]), int(candidate[2:4]), int(candidate[4:6])
    century = 1900 if yy > datetime.now(UTC).year % 100 else 2000
    try:
        date(century + yy, mm, dd)
    except ValueError:
        return False
    if candidate[10] not in "01":
        return False
    return luhn_valid(candidate)


def _phone_plausible(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    if not 10 <= len(digits) <= 13:
        return False
    return match.startswith(("+", "0", "(0)"))


def scrub_text(text: str) -> str:
    text = SA_ID_RE.sub(lambda m: SA_ID_TOKEN if sa_id_valid(m.group()) else m.group(), text)
    text = EMAIL_RE.sub(EMAIL_TOKEN, text)
    text = PHONE_RE.sub(lambda m: PHONE_TOKEN if _phone_plausible(m.group()) else m.group(), text)
    return text


def scrub_pii(value: Any) -> Any:
    """Recursively replace emails, phone numbers and valid SA ID numbers in strings."""
    if isinstance(value, BaseModel):
        return scrub_pii(value.model_dump(mode="json"))
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {k: scrub_pii(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_pii(v) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub_pii(v) for v in value)
    return value
