"""HTTP transport via httpx's ASGI transport; SSE stream yields events."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from mcp_gateway import AUTH_DENIED
from mcp_gateway.events import Event
from mcp_gateway.transport.http import extract_api_key, format_sse
from tests.conftest import KEY_A, KEY_B, rpc


@pytest.fixture
def app(gateway):
    return gateway.asgi()


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as c:
        yield c


def test_extract_api_key_prefers_bearer_then_header():
    assert extract_api_key({"authorization": "Bearer abc"}) == "abc"
    assert extract_api_key({"authorization": "bearer   "}) is None
    assert extract_api_key({"x-api-key": "k"}) == "k"
    assert extract_api_key({}) is None


def test_format_sse_multiline_data():
    assert format_sse("e", "a\nb") == "event: e\ndata: a\ndata: b\n\n"
    assert format_sse("e", "") == "event: e\ndata: \n\n"


async def test_post_mcp_initialize(client):
    r = await client.post("/mcp", json=rpc("initialize", {"protocolVersion": "2025-03-26"}))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["result"]["serverInfo"]["name"] == "test-gateway"


async def test_post_mcp_tool_call_with_bearer(client):
    r = await client.post(
        "/mcp",
        json=rpc("tools/call", {"name": "echo", "arguments": {"text": "hey"}}),
        headers={"Authorization": f"Bearer {KEY_A}"},
    )
    assert r.json()["result"]["structuredContent"] == {"text": "hey"}


async def test_post_mcp_tool_call_with_x_api_key_header(client):
    r = await client.post(
        "/mcp", json=rpc("tools/list"), headers={"X-API-Key": KEY_B}
    )
    assert "echo" in {t["name"] for t in r.json()["result"]["tools"]}


async def test_post_mcp_without_key_is_denied_in_body(client):
    r = await client.post("/mcp", json=rpc("tools/list"))
    assert r.status_code == 200  # JSON-RPC carries the error, transport stays 200
    assert r.json()["error"]["code"] == AUTH_DENIED


async def test_post_mcp_malformed_body(client):
    r = await client.post("/mcp", content=b"{oops", headers={"content-type": "application/json"})
    assert r.json()["error"]["code"] == -32700


async def test_post_mcp_notification_is_202(client):
    r = await client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202 and r.content == b""


async def test_healthz(client):
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok" and "echo" in r.json()["tools"]


async def test_sse_requires_auth(client):
    r = await client.get("/mcp/events")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AUTH_DENIED


async def test_sse_stream_yields_endpoint_then_tenant_events(gateway, client):
    async def produce():
        await asyncio.sleep(0.05)
        gateway.events.publish(Event("tool_call", {"tool": "echo", "outcome": "ok"}, "tenant-a"))
        gateway.events.publish(Event("tool_call", {"tool": "x", "outcome": "ok"}, "tenant-b"))
        await asyncio.sleep(0.02)
        gateway.events.close()

    producer = asyncio.create_task(produce())
    r = await client.get("/mcp/events", headers={"Authorization": f"Bearer {KEY_A}"})
    await producer
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    body = r.text
    assert body.startswith("event: endpoint\ndata: /mcp\n\n")
    assert '"tool": "echo"' in body
    assert '"tool": "x"' not in body  # tenant-b's event never reaches tenant-a's stream


async def test_sse_stream_carries_real_tool_call_events(gateway, client):
    async def drive():
        await asyncio.sleep(0.05)
        await client.post(
            "/mcp",
            json=rpc("tools/call", {"name": "echo", "arguments": {"text": "via http"}}),
            headers={"Authorization": f"Bearer {KEY_A}"},
        )
        await asyncio.sleep(0.02)
        gateway.events.close()

    driver = asyncio.create_task(drive())
    r = await client.get("/mcp/events", headers={"Authorization": f"Bearer {KEY_A}"})
    await driver
    events = [line for line in r.text.splitlines() if line.startswith("data: {")]
    payload = json.loads(events[0][len("data: "):])
    assert payload["tool"] == "echo" and payload["outcome"] == "ok"
    assert "via http" not in r.text  # arguments never leave the audit hash


async def test_post_mcp_body_over_limit_is_413_before_parsing(client):
    body = json.dumps(rpc("ping", {"pad": "x" * (2 * 1024 * 1024)})).encode()
    r = await client.post("/mcp", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.json()["error"]["code"] == -32600
    assert r.json()["error"]["data"]["reason"] == "body_too_large"


async def test_body_limit_is_configurable_through_asgi(gateway):
    transport = httpx.ASGITransport(app=gateway.asgi(max_body_bytes=200))
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as c:
        small = await c.post("/mcp", json=rpc("ping"))
        assert small.status_code == 200 and small.json()["result"] == {}
        big = await c.post("/mcp", json=rpc("ping", {"pad": "y" * 300}))
        assert big.status_code == 413
