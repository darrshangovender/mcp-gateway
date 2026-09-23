"""Tenancy: cross-tenant reads blocked, contextvar isolation under concurrency."""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_gateway import TENANT_VIOLATION, TenantContext, TenantViolation, assert_tenant_owned
from mcp_gateway.tenancy import TenantContextError, current_tenant, tenant_filter
from tests.conftest import KEY_A, KEY_B, call_tool


def test_no_tenant_bound_raises():
    assert TenantContext.get() is None
    with pytest.raises(TenantContextError):
        current_tenant()
    with pytest.raises(TenantContextError):
        tenant_filter()


def test_context_binds_and_restores():
    with TenantContext("t1"):
        assert current_tenant() == "t1"
        with TenantContext("t2"):
            assert current_tenant() == "t2"
        assert current_tenant() == "t1"
    assert TenantContext.get() is None


def test_tenant_filter_sql_and_matching():
    with TenantContext("acme"):
        tf = tenant_filter()
        assert tf.sql == "tenant_id = ?"
        assert tf.params == ("acme",)
        assert tf.matches({"tenant_id": "acme"})
        assert not tf.matches({"tenant_id": "globex"})
        assert tenant_filter("c.tenant_id").sql == "c.tenant_id = ?"


def test_assert_tenant_owned_passes_own_rows_and_untagged():
    payload = {"rows": [{"tenant_id": "a", "x": 1}, {"x": 2}], "meta": {"count": 2}}
    assert assert_tenant_owned(payload, "a") is payload


def test_assert_tenant_owned_finds_nested_foreign_row():
    payload = {"rows": [{"tenant_id": "a"}, {"nested": [{"tenant_id": "b"}]}]}
    with pytest.raises(TenantViolation) as exc:
        assert_tenant_owned(payload, "a")
    assert exc.value.code == TENANT_VIOLATION
    assert exc.value.data["paths"] == ["$.rows[1].nested[0]"]


async def test_cross_tenant_read_is_blocked_by_filter(gateway):
    a = await call_tool(gateway, KEY_A, "list_rows")
    b = await call_tool(gateway, KEY_B, "list_rows")
    assert {r["name"] for r in a["result"]["structuredContent"]["rows"]} == {"Alice", "Amir"}
    assert {r["name"] for r in b["result"]["structuredContent"]["rows"]} == {"Bongani"}


async def test_post_call_check_catches_tool_that_forgot_the_filter(gateway, audit):
    own = await call_tool(gateway, KEY_A, "leaky_lookup", {"id": 1})
    assert own["result"]["structuredContent"]["name"] == "Alice"

    leak = await call_tool(gateway, KEY_A, "leaky_lookup", {"id": 3})
    assert leak["error"]["code"] == TENANT_VIOLATION
    assert "Bongani" not in str(leak)
    assert audit.records[-1].outcome == "denied"
    assert audit.records[-1].error_code == TENANT_VIOLATION


async def test_contextvar_isolation_under_concurrent_calls(gateway):
    tasks = []
    for i in range(20):
        key = KEY_A if i % 2 == 0 else KEY_B
        tasks.append(call_tool(gateway, key, "slow", {"text": str(i)}))
    replies = await asyncio.gather(*tasks)
    for i, reply in enumerate(replies):
        expected = "tenant-a" if i % 2 == 0 else "tenant-b"
        assert reply["result"]["structuredContent"]["text"] == f"{expected}:{expected}:{i}"
    assert TenantContext.get() is None


async def test_tenant_not_left_bound_after_error(gateway):
    await call_tool(gateway, KEY_A, "boom")
    assert TenantContext.get() is None


async def test_tenant_violation_reply_does_not_name_the_other_tenant(gateway, audit):
    leak = await call_tool(gateway, KEY_A, "leaky_lookup", {"id": 3})
    err = leak["error"]
    assert err["code"] == TENANT_VIOLATION
    assert err["data"] == {"reason": "tenant_violation", "tool": "leaky_lookup"}
    assert "tenant-b" not in json.dumps(leak)
    # ...but the operator still gets the specifics.
    assert "tenant-b" in audit.records[-1].denial_reason


async def test_two_tenants_concurrently_never_see_each_others_rows(gateway):
    def rows_of(reply):
        return {r["tenant_id"] for r in reply["result"]["structuredContent"]["rows"]}

    async def drive(key: str, tag: str):
        seen = []
        for i in range(10):
            # Interleave an async tool (yields mid-call) with a sync data read.
            slow = await call_tool(gateway, key, "slow", {"text": f"{tag}{i}"})
            rows = await call_tool(gateway, key, "list_rows")
            seen.append((slow["result"]["structuredContent"]["text"], rows_of(rows)))
        return seen

    a, b = await asyncio.gather(drive(KEY_A, "a"), drive(KEY_B, "b"))
    for i, (text, rows) in enumerate(a):
        assert text == f"tenant-a:tenant-a:a{i}" and rows == {"tenant-a"}
    for i, (text, rows) in enumerate(b):
        assert text == f"tenant-b:tenant-b:b{i}" and rows == {"tenant-b"}
    assert TenantContext.get() is None
