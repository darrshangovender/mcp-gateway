"""Guardrails: oversized payload, allow-list, deny_if, PII scrub with SA ID Luhn."""

from __future__ import annotations

import pytest

from mcp_gateway import GUARDRAIL_DENIED, GuardrailDenied, ToolPolicy, scrub_pii
from mcp_gateway.guardrails import check_input, luhn_valid, payload_size, sa_id_valid, scrub_text
from tests.conftest import KEY_A, call, call_tool

VALID_SA_ID = "9001015009086"  # 1990-01-01, checksum-valid
INVALID_SA_ID = "9001015009087"  # last digit wrong


def test_luhn():
    assert luhn_valid("79927398713")
    assert not luhn_valid("79927398710")
    assert not luhn_valid("abc")


def test_sa_id_validation_requires_date_and_checksum():
    assert sa_id_valid(VALID_SA_ID)
    assert not sa_id_valid(INVALID_SA_ID)
    assert not sa_id_valid("9013015009087")  # month 13
    assert not sa_id_valid("123")


def test_scrub_email_phone_and_id():
    text = (
        f"Contact thandi@example.co.za or +27 82 123 4567 / 031 555 0123. "
        f"ID {VALID_SA_ID}; ref {INVALID_SA_ID}; order 1234-5678."
    )
    out = scrub_text(text)
    assert "thandi@" not in out and "[EMAIL]" in out
    assert "+27 82" not in out and "031 555" not in out
    assert out.count("[PHONE]") == 2
    assert VALID_SA_ID not in out and "[SA_ID]" in out
    assert INVALID_SA_ID in out  # not a real ID, so not scrubbed
    assert "1234-5678" in out  # short reference numbers survive


def test_scrub_is_recursive_over_structures():
    payload = {
        "rows": [{"email": "a@b.co", "tags": ("x@y.org", 5)}],
        "phone": "0821234567",
        "count": 2,
    }
    out = scrub_pii(payload)
    assert out["rows"][0]["email"] == "[EMAIL]"
    assert out["rows"][0]["tags"] == ("[EMAIL]", 5)
    assert out["phone"] == "[PHONE]"
    assert out["count"] == 2


def test_payload_size_counts_encoded_bytes():
    assert payload_size({"a": "é"}) == len(b'{"a":"\xc3\xa9"}')


def test_check_input_payload_too_large():
    policy = ToolPolicy(max_payload_bytes=10)
    with pytest.raises(GuardrailDenied) as exc:
        check_input(policy, "t", {"text": "x" * 50}, None)
    assert exc.value.code == GUARDRAIL_DENIED
    assert exc.value.data["reason"] == "payload_too_large"


def test_check_input_allow_list():
    policy = ToolPolicy().with_allowed_args("query")
    check_input(policy, "t", {"query": "ok"}, None)
    with pytest.raises(GuardrailDenied) as exc:
        check_input(policy, "t", {"query": "ok", "sql": "DROP"}, None)
    assert exc.value.data["arguments"] == ["sql"]


def test_check_input_deny_if_receives_principal():
    seen = {}

    def deny(args, principal):
        seen["principal"] = principal
        return "nope" if args.get("x") else None

    policy = ToolPolicy(deny_if=deny)
    check_input(policy, "t", {"x": 0}, "the-principal")
    assert seen["principal"] == "the-principal"
    with pytest.raises(GuardrailDenied, match="nope"):
        check_input(policy, "t", {"x": 1}, "the-principal")


async def test_oversized_payload_denied_end_to_end(gateway, audit):
    reply = await call_tool(gateway, KEY_A, "strict", {"text": "y" * 200})
    assert reply["error"]["code"] == GUARDRAIL_DENIED
    rec = audit.records[-1]
    assert rec.outcome == "denied" and "exceeds" in rec.denial_reason


async def test_unknown_argument_denied_end_to_end(gateway):
    reply = await call_tool(gateway, KEY_A, "strict", {"text": "ok", "extra": 1})
    assert reply["error"]["code"] == GUARDRAIL_DENIED
    assert reply["error"]["data"]["reason"] == "argument_not_allowed"


async def test_deny_if_denied_end_to_end(gateway, audit):
    reply = await call_tool(gateway, KEY_A, "strict", {"text": "forbidden"})
    assert reply["error"]["code"] == GUARDRAIL_DENIED
    assert "forbidden word" in reply["error"]["message"]
    assert audit.records[-1].denial_reason.endswith("forbidden word")


async def test_output_pii_is_scrubbed_end_to_end(gateway):
    reply = await call_tool(gateway, KEY_A, "list_rows")
    rows = reply["result"]["structuredContent"]["rows"]
    assert all(r["email"] == "[EMAIL]" for r in rows)
    assert "example.com" not in reply["result"]["content"][0]["text"]


async def test_echo_scrubs_pii_the_client_sent_in(gateway):
    reply = await call_tool(gateway, KEY_A, "echo", {"text": f"my id is {VALID_SA_ID}"})
    assert reply["result"]["structuredContent"]["text"] == "my id is [SA_ID]"


async def test_prompt_output_is_scrubbed(gateway):
    pii = f"bob@example.com, 082 123 4567, id {VALID_SA_ID}"
    reply = await call(gateway, KEY_A, "prompts/get", {"name": "greet", "arguments": {"name": pii}})
    text = reply["result"]["messages"][0]["content"]["text"]
    assert text == "Say hello to [EMAIL], [PHONE], id [SA_ID]"
