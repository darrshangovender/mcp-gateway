"""Protocol conformance: every MCP method, malformed JSON, unknown method, bad params."""

from __future__ import annotations

import json
import logging

import pytest

from mcp_gateway import (
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    PROTOCOL_VERSION,
    Dispatcher,
    GatewayError,
    RequestContext,
)
from mcp_gateway.protocol import (
    INTERNAL_ERROR,
    INVALID_REQUEST,
    PARSE_ERROR,
    JSONRPCRequest,
    JSONRPCResponse,
)
from tests.conftest import KEY_A, call, rpc

INIT_PARAMS = {"protocolVersion": "2025-03-26", "capabilities": {},
               "clientInfo": {"name": "t", "version": "1"}}


async def test_initialize_returns_server_info_and_pinned_protocol(gateway):
    reply = await call(gateway, None, "initialize", INIT_PARAMS)
    assert reply["id"] == 1
    assert reply["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert reply["result"]["serverInfo"]["name"] == "test-gateway"
    assert "tools" in reply["result"]["capabilities"]


async def test_initialize_requires_protocol_version(gateway):
    reply = await call(gateway, None, "initialize", {"capabilities": {}})
    assert reply["error"]["code"] == INVALID_PARAMS
    assert reply["error"]["data"]["errors"][0]["loc"] == ["protocolVersion"]


async def test_initialized_notification_gets_no_reply(gateway):
    msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    reply = await gateway.dispatcher.dispatch(msg, RequestContext())
    assert reply is None


async def test_ping(gateway):
    reply = await call(gateway, None, "ping")
    assert reply["result"] == {}


async def test_tools_list_returns_definitions_with_schemas(gateway):
    reply = await call(gateway, KEY_A, "tools/list")
    tools = {t["name"]: t for t in reply["result"]["tools"]}
    assert "echo" in tools
    assert tools["echo"]["inputSchema"]["properties"]["text"]["type"] == "string"
    assert tools["echo"]["description"] == "Echo text back."


async def test_tools_call_returns_text_and_structured_content(gateway):
    reply = await call(gateway, KEY_A, "tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    result = reply["result"]
    assert result["isError"] is False
    assert result["structuredContent"] == {"text": "hi"}
    assert json.loads(result["content"][0]["text"]) == {"text": "hi"}


async def test_tools_call_unknown_tool_is_invalid_params(gateway):
    reply = await call(gateway, KEY_A, "tools/call", {"name": "nope", "arguments": {}})
    assert reply["error"]["code"] == INVALID_PARAMS
    assert reply["error"]["data"]["tool"] == "nope"


async def test_tools_call_missing_name_is_invalid_params(gateway):
    reply = await call(gateway, KEY_A, "tools/call", {"arguments": {}})
    assert reply["error"]["code"] == INVALID_PARAMS


async def test_tools_call_bad_argument_type_is_invalid_params(gateway):
    reply = await call(gateway, KEY_A, "tools/call", {"name": "echo", "arguments": {"text": 5}})
    assert reply["error"]["code"] == INVALID_PARAMS
    assert reply["error"]["data"]["errors"][0]["loc"] == ["text"]


async def test_resources_list_and_read(gateway):
    listed = await call(gateway, KEY_A, "resources/list")
    assert listed["result"]["resources"][0]["uri"] == "mem://about"
    read = await call(gateway, KEY_A, "resources/read", {"uri": "mem://about"})
    contents = read["result"]["contents"][0]
    assert contents["uri"] == "mem://about"
    assert contents["text"].startswith("tenant=tenant-a")


async def test_resources_read_unknown_uri(gateway):
    reply = await call(gateway, KEY_A, "resources/read", {"uri": "mem://missing"})
    assert reply["error"]["code"] == INVALID_PARAMS


async def test_prompts_list_and_get(gateway):
    listed = await call(gateway, KEY_A, "prompts/list")
    p = listed["result"]["prompts"][0]
    assert p["name"] == "greet"
    assert p["arguments"][0]["required"] is True
    got = await call(gateway, KEY_A, "prompts/get", {"name": "greet", "arguments": {"name": "Zo"}})
    assert got["result"]["messages"][0]["content"]["text"] == "Say hello to Zo"


async def test_prompts_get_missing_required_argument(gateway):
    reply = await call(gateway, KEY_A, "prompts/get", {"name": "greet", "arguments": {}})
    assert reply["error"]["code"] == INVALID_PARAMS


async def test_unknown_method_is_32601(gateway):
    reply = await call(gateway, KEY_A, "tools/explode")
    assert reply["error"]["code"] == METHOD_NOT_FOUND
    assert reply["id"] == 1


async def test_malformed_json_is_parse_error(gateway):
    raw = await gateway.dispatcher.dispatch_raw("{not json", RequestContext())
    reply = json.loads(raw)
    assert reply["error"]["code"] == PARSE_ERROR
    assert reply["id"] is None


async def test_non_object_message_is_invalid_request(gateway):
    reply = await gateway.dispatcher.dispatch("just a string", RequestContext())
    assert reply["error"]["code"] == INVALID_REQUEST


async def test_missing_jsonrpc_version_is_invalid_request(gateway):
    reply = await gateway.dispatcher.dispatch({"id": 7, "method": "ping"}, RequestContext())
    assert reply["error"]["code"] == INVALID_REQUEST
    assert reply["id"] == 7


async def test_batch_dispatch_returns_one_reply_per_request(gateway):
    batch = [rpc("ping", id_=1), rpc("nope", id_=2), {"jsonrpc": "2.0", "method": "ping"}]
    replies = await gateway.dispatcher.dispatch(batch, RequestContext())
    assert [r["id"] for r in replies] == [1, 2]
    assert replies[1]["error"]["code"] == METHOD_NOT_FOUND


async def test_empty_batch_is_invalid_request(gateway):
    reply = await gateway.dispatcher.dispatch([], RequestContext())
    assert reply["error"]["code"] == INVALID_REQUEST


async def test_string_ids_round_trip(gateway):
    reply = await call(gateway, None, "ping", id_="abc-123")
    assert reply["id"] == "abc-123"


async def test_handler_exception_is_internal_error_without_traceback():
    d = Dispatcher()

    @d.method("crash")
    async def crash(params, ctx):
        raise RuntimeError("db password is hunter2")

    reply = await d.dispatch(rpc("crash"), RequestContext())
    assert reply["error"]["code"] == INTERNAL_ERROR
    assert "hunter2" not in json.dumps(reply)


async def test_handler_exception_is_logged_server_side(caplog):
    d = Dispatcher()

    @d.method("crash")
    async def crash(params, ctx):
        raise RuntimeError("db password is hunter2")

    with caplog.at_level(logging.ERROR, logger="mcp_gateway"):
        reply = await d.dispatch(rpc("crash"), RequestContext())
    assert reply["error"] == {"code": INTERNAL_ERROR, "message": "internal error"}
    assert "hunter2" in caplog.text and "RuntimeError" in caplog.text


async def test_gateway_error_code_is_preserved():
    d = Dispatcher()

    @d.method("deny")
    def deny(params, ctx):
        raise GatewayError("no", code=-32050, data={"why": "because"})

    reply = await d.dispatch(rpc("deny"), RequestContext())
    assert reply["error"] == {"code": -32050, "message": "no", "data": {"why": "because"}}


def test_request_model_distinguishes_notification():
    assert JSONRPCRequest(jsonrpc="2.0", method="x").is_notification
    assert not JSONRPCRequest(jsonrpc="2.0", id=None, method="x").is_notification
    with pytest.raises(ValueError):
        JSONRPCRequest(jsonrpc="1.0", method="x")


def test_response_to_dict_shapes():
    ok = JSONRPCResponse(id=1, result={"a": 1}).to_dict()
    assert ok == {"jsonrpc": "2.0", "id": 1, "result": {"a": 1}}
    err = JSONRPCResponse(id=1, error={"code": -1, "message": "m"}).to_dict()
    assert "result" not in err and err["error"] == {"code": -1, "message": "m"}
