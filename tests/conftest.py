"""Shared fixtures: a small gateway with two tenants and a handful of tools."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import BaseModel, Field

from mcp_gateway import (
    APIKeyAuth,
    CallContext,
    Gateway,
    MemoryAuditLog,
    MemoryRateLimiter,
    PromptArgument,
    RecordingTracer,
    RequestContext,
    Tier,
    ToolPolicy,
    prompt,
    resource,
    tenant_filter,
    tool,
)

KEY_A = "key-for-tenant-a"
KEY_B = "key-for-tenant-b"
KEY_READONLY = "key-readonly-a"

ROWS = [
    {"id": 1, "tenant_id": "tenant-a", "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "tenant_id": "tenant-a", "name": "Amir", "email": "amir@example.co.za"},
    {"id": 3, "tenant_id": "tenant-b", "name": "Bongani", "email": "bongani@example.com"},
]


class EchoIn(BaseModel):
    text: str = Field(min_length=1)


class EchoOut(BaseModel):
    text: str


class LookupIn(BaseModel):
    id: int


class Row(BaseModel):
    id: int
    tenant_id: str
    name: str
    email: str


class RowsOut(BaseModel):
    rows: list[Row]


class EmptyIn(BaseModel):
    pass


@tool("echo", input_model=EchoIn, output_model=EchoOut, description="Echo text back.")
def echo(args: EchoIn, ctx: CallContext) -> EchoOut:
    return EchoOut(text=args.text)


@tool("list_rows", input_model=EmptyIn, output_model=RowsOut, scopes=("rows:read",))
def list_rows(args: EmptyIn, ctx: CallContext) -> RowsOut:
    tf = tenant_filter()
    return RowsOut(rows=[Row(**r) for r in ROWS if tf.matches(r)])


@tool("leaky_lookup", input_model=LookupIn, output_model=Row, scopes=("rows:read",))
def leaky_lookup(args: LookupIn, ctx: CallContext) -> Row:
    """Deliberately forgets the tenant filter so the post-call check has work to do."""
    return Row(**next(r for r in ROWS if r["id"] == args.id))


@tool(
    "strict",
    input_model=EchoIn,
    output_model=EchoOut,
    policy=ToolPolicy(
        max_payload_bytes=64,
        allowed_args=frozenset({"text"}),
        deny_if=lambda a, p: "forbidden word" if "forbidden" in a.get("text", "") else None,
    ),
)
def strict(args: EchoIn, ctx: CallContext) -> EchoOut:
    return EchoOut(text=args.text)


@tool("slow", input_model=EchoIn, output_model=EchoOut)
async def slow(args: EchoIn, ctx: CallContext) -> EchoOut:
    await asyncio.sleep(0.01)
    return EchoOut(text=f"{ctx.tenant_id}:{tenant_filter().tenant_id}:{args.text}")


@tool("boom", input_model=EmptyIn)
def boom(args: EmptyIn, ctx: CallContext) -> dict[str, Any]:
    raise RuntimeError("secret internal detail")


@tool("limited", input_model=EmptyIn, rate_tier="tiny")
def limited(args: EmptyIn, ctx: CallContext) -> dict[str, Any]:
    return {"ok": True}


@resource("mem://about", name="about", mime_type="text/plain")
def about(ctx: CallContext) -> str:
    return f"tenant={ctx.tenant_id} contact=ops@example.com"


@prompt("greet", arguments=[PromptArgument(name="name", required=True)])
def greet(arguments: dict[str, str], ctx: CallContext) -> str:
    return f"Say hello to {arguments['name']}"


TIERS = {
    "standard": Tier(capacity=100, refill_per_second=100.0),
    "tiny": Tier(capacity=2, refill_per_second=0.001),
}


def make_auth() -> APIKeyAuth:
    auth = APIKeyAuth(salt="test-salt")
    auth.add_key(
        KEY_A, tenant_id="tenant-a", key_id="a-1",
        scopes=["tools:list", "tools:call", "resources:read", "prompts:read", "rows:read"],
    )
    auth.add_key(
        KEY_B, tenant_id="tenant-b", key_id="b-1",
        scopes=["tools:list", "tools:call", "resources:read", "rows:read"],
    )
    auth.add_key(KEY_READONLY, tenant_id="tenant-a", key_id="a-ro", scopes=["tools:list"])
    return auth


@pytest.fixture
def audit() -> MemoryAuditLog:
    return MemoryAuditLog()


@pytest.fixture
def tracer() -> RecordingTracer:
    return RecordingTracer()


@pytest.fixture
def gateway(audit: MemoryAuditLog, tracer: RecordingTracer) -> Gateway:
    return Gateway(
        tools=[echo, list_rows, leaky_lookup, strict, slow, boom, limited],
        resources=[about],
        prompts=[greet],
        auth=make_auth(),
        limiter=MemoryRateLimiter(TIERS),
        audit=audit,
        tracer=tracer,
        name="test-gateway",
    )


def rpc(method: str, params: dict[str, Any] | None = None, id_: int | str = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


async def call(gateway: Gateway, key: str | None, method: str, params: Any = None, id_: Any = 1):
    return await gateway.dispatcher.dispatch(
        rpc(method, params, id_), RequestContext(api_key=key, transport="test")
    )


async def call_tool(gateway: Gateway, key: str | None, name: str, arguments: Any = None):
    return await call(gateway, key, "tools/call", {"name": name, "arguments": arguments or {}})
