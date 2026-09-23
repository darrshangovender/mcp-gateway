"""Gateway pipeline: tool errors are results not protocol errors, output models
are enforced, and the example CRM server behaves as the README claims."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel

from mcp_gateway import (
    AUTH_DENIED,
    GUARDRAIL_DENIED,
    RATE_LIMITED,
    APIKeyAuth,
    Gateway,
    MemoryRateLimiter,
    RequestContext,
    Tier,
    tool,
)
from mcp_gateway.protocol import INTERNAL_ERROR
from tests.conftest import KEY_A, call, call_tool


async def test_tool_exception_is_an_error_result_not_a_protocol_error(gateway, audit):
    reply = await call_tool(gateway, KEY_A, "boom")
    assert "error" not in reply
    assert reply["result"]["isError"] is True
    assert reply["result"]["content"][0]["text"] == "tool error: RuntimeError"
    assert "secret internal detail" not in str(reply)
    assert audit.records[-1].outcome == "error"
    assert "secret internal detail" in audit.records[-1].denial_reason


async def test_output_model_mismatch_is_internal_error():
    class In(BaseModel):
        pass

    class Out(BaseModel):
        value: int

    @tool("bad_shape", input_model=In, output_model=Out)
    def bad_shape(args, ctx):
        return {"value": "not-an-int"}

    auth = APIKeyAuth(salt="s")
    auth.add_key("k", tenant_id="t", scopes=["tools:call"])
    gw = Gateway(tools=[bad_shape], auth=auth)
    reply = await call_tool(gw, "k", "bad_shape")
    assert reply["error"]["code"] == INTERNAL_ERROR
    assert "output model" in reply["error"]["message"]


async def test_principal_rate_tier_overrides_tool_tier():
    class In(BaseModel):
        pass

    @tool("t", input_model=In, rate_tier="big")
    def t(args, ctx):
        return {"ok": True}

    auth = APIKeyAuth(salt="s")
    auth.add_key("k", tenant_id="t", scopes=["tools:call"], rate_tier="small")
    tiers = {"big": Tier(100, 1.0), "small": Tier(1, 0.001), "standard": Tier(5, 1.0)}
    gw = Gateway(tools=[t], auth=auth, limiter=MemoryRateLimiter(tiers))
    assert "result" in await call_tool(gw, "k", "t")
    denied = await call_tool(gw, "k", "t")
    assert denied["error"]["code"] == RATE_LIMITED and denied["error"]["data"]["tier"] == "small"


async def test_principal_is_cached_on_context_for_the_request(gateway):
    ctx = RequestContext(api_key=KEY_A, transport="test")
    await gateway.dispatcher.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ctx
    )
    assert ctx.principal is not None and ctx.principal.tenant_id == "tenant-a"


async def test_events_published_per_call_scoped_to_tenant(gateway):
    with gateway.events.subscribe("tenant-a") as qa, gateway.events.subscribe("tenant-b") as qb:
        await call_tool(gateway, KEY_A, "echo", {"text": "e"})
        assert qa.get_nowait().data["tool"] == "echo"
        assert qb.empty()


# --- the example CRM server -------------------------------------------------


@pytest.fixture
def crm():
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    mod = importlib.import_module("examples.crm_server")
    return mod


async def test_crm_tenant_a_cannot_read_tenant_b(crm):
    gw = crm.build_gateway()
    own = await call_tool(gw, crm.ACME_KEY, "get_customer", {"customer_id": 1})
    assert own["result"]["structuredContent"]["name"] == "Thandi Mkhize"
    other = await call_tool(gw, crm.ACME_KEY, "get_customer", {"customer_id": 4})
    assert other["result"]["isError"] is True
    assert "Sipho" not in str(other)


async def test_crm_create_note_requires_notes_write(crm):
    gw = crm.build_gateway()
    args = {"customer_id": 4, "body": "hello"}
    denied = await call_tool(gw, crm.GLOBEX_KEY, "create_note", args)
    assert denied["error"]["code"] == AUTH_DENIED and "notes:write" in denied["error"]["message"]
    ok = await call_tool(gw, crm.ACME_KEY, "create_note", {"customer_id": 1, "body": "hello"})
    assert ok["result"]["structuredContent"]["author"] == "acme-agent"


async def test_crm_outputs_have_emails_and_ids_scrubbed(crm):
    gw = crm.build_gateway()
    r = await call_tool(gw, crm.ACME_KEY, "search_customers", {"query": "thandi"})
    row = r["result"]["structuredContent"]["customers"][0]
    assert row["email"] == "[EMAIL]" and row["phone"] == "[PHONE]" and row["id_number"] == "[SA_ID]"


async def test_crm_deny_if_guardrail(crm):
    gw = crm.build_gateway()
    r = await call_tool(gw, crm.ACME_KEY, "create_note", {"customer_id": 1, "body": "DROP TABLE x"})
    assert r["error"]["code"] == GUARDRAIL_DENIED


async def test_crm_rate_limit_trips_on_free_tier(crm):
    gw = crm.build_gateway()
    outcomes = []
    for _ in range(4):
        r = await call_tool(gw, crm.GLOBEX_KEY, "list_open_invoices")
        outcomes.append("ok" if "result" in r else r["error"]["code"])
    assert outcomes == ["ok", "ok", "ok", RATE_LIMITED]


async def test_crm_resource_read(crm):
    gw = crm.build_gateway()
    r = await call(gw, crm.ACME_KEY, "resources/read", {"uri": "crm://schema"})
    assert "CREATE TABLE customers" in r["result"]["contents"][0]["text"]
