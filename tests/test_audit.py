"""Audit: every call logged, args hashed not stored, JSONL append-only."""

from __future__ import annotations

import json

from pydantic import BaseModel

from mcp_gateway import AuditRecord, Gateway, JSONLAuditLog, hash_args, tool
from tests.conftest import KEY_A, KEY_B, call, call_tool, make_auth


def test_hash_args_is_canonical_and_stable():
    assert hash_args({"b": 1, "a": [1, 2]}) == hash_args({"a": [1, 2], "b": 1})
    assert hash_args({"a": 1}) != hash_args({"a": 2})
    assert len(hash_args({})) == 64


async def test_every_outcome_is_logged(gateway, audit):
    await call_tool(gateway, KEY_A, "echo", {"text": "ok"})  # ok
    await call_tool(gateway, KEY_A, "boom")  # tool error
    await call_tool(gateway, None, "echo", {"text": "x"})  # auth denial
    await call_tool(gateway, KEY_A, "nope")  # unknown tool -> error
    outcomes = [r.outcome for r in audit.records]
    assert outcomes == ["ok", "error", "denied", "error"]
    assert audit.records[2].error_code == -32002
    assert audit.records[2].tenant_id is None  # never authenticated
    assert audit.records[0].tenant_id == "tenant-a" and audit.records[0].key_id == "a-1"


async def test_args_are_hashed_not_stored(gateway, audit):
    secret = "my email is alice@example.com and my id is 9001015009086"
    await call_tool(gateway, KEY_A, "echo", {"text": secret})
    rec = audit.records[-1]
    assert rec.args_hash == hash_args({"text": secret})
    dumped = rec.model_dump_json()
    assert "alice@example.com" not in dumped and "9001015009086" not in dumped


async def test_latency_and_tool_recorded(gateway, audit):
    await call_tool(gateway, KEY_A, "slow", {"text": "z"})
    rec = audit.records[-1]
    assert rec.tool == "slow" and rec.method == "tools/call"
    assert rec.latency_ms >= 5.0
    assert rec.transport == "test"


async def test_denial_reason_is_recorded(gateway, audit):
    await call_tool(gateway, KEY_B, "leaky_lookup", {"id": 1})
    rec = audit.records[-1]
    assert rec.outcome == "denied"
    assert "tenant-a" in rec.denial_reason


def test_jsonl_log_appends_and_reads_back(tmp_path):
    log = JSONLAuditLog(tmp_path / "audit" / "log.jsonl")
    r1 = AuditRecord(method="tools/call", tool="a", outcome="ok", args_hash="x" * 64)
    r2 = AuditRecord(method="tools/call", tool="b", outcome="denied", error_code=-32001,
                     denial_reason="nope")
    log.write(r1)
    log.write(r2)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["denial_reason"] == "nope"
    assert "error_code" not in json.loads(lines[0])  # exclude_none keeps lines tight
    assert [r.tool for r in log.read_all()] == ["a", "b"]


def test_jsonl_read_all_missing_file_is_empty(tmp_path):
    assert JSONLAuditLog(tmp_path / "none.jsonl").read_all() == []


async def test_malformed_tools_call_is_audited(gateway, audit):
    # No 'name' at all, then arguments of the wrong shape: neither may skip the log.
    await call(gateway, KEY_A, "tools/call", {"arguments": {}})
    await call(gateway, KEY_A, "tools/call", {"name": "echo", "arguments": ["not", "a", "dict"]})
    await call(gateway, None, "tools/call", None)
    assert [r.outcome for r in audit.records[-3:]] == ["error", "error", "error"]
    assert all(r.error_code == -32602 and r.method == "tools/call" for r in audit.records[-3:])
    assert audit.records[-3].tool is None and audit.records[-2].tool == "echo"


async def test_tool_exception_text_is_scrubbed_before_audit(audit):
    class In(BaseModel):
        pass

    @tool("chatty_failure", input_model=In)
    def chatty_failure(args, ctx):
        raise ValueError("no such user thandi@example.co.za / 082 123 4567")

    gw = Gateway(tools=[chatty_failure], auth=make_auth(), audit=audit)
    reply = await call_tool(gw, KEY_A, "chatty_failure")
    assert reply["result"]["isError"] is True
    reason = audit.records[-1].denial_reason
    assert reason.startswith("ValueError:") and "[EMAIL]" in reason and "[PHONE]" in reason
    assert "thandi@" not in reason and "082 123" not in reason
