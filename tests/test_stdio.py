"""Stdio transport: newline-delimited JSON in, one reply line out, key from env."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

from mcp_gateway.transport.stdio import StdioTransport
from tests.conftest import KEY_A, rpc


async def test_handle_line_dispatches_and_skips_blank_lines(gateway):
    t = StdioTransport(gateway.dispatcher, api_key=KEY_A)
    assert await t.handle_line("") is None
    assert await t.handle_line("   \n") is None
    reply = json.loads(await t.handle_line(json.dumps(rpc("ping")) + "\n"))
    assert reply["result"] == {}


async def test_handle_line_accepts_bytes_and_uses_key(gateway):
    t = StdioTransport(gateway.dispatcher, api_key=KEY_A)
    line = json.dumps(rpc("tools/call", {"name": "echo", "arguments": {"text": "b"}})).encode()
    reply = json.loads(await t.handle_line(line))
    assert reply["result"]["structuredContent"] == {"text": "b"}


async def test_api_key_read_from_environment(gateway, monkeypatch):
    monkeypatch.setenv("MCP_GATEWAY_API_KEY", KEY_A)
    t = StdioTransport(gateway.dispatcher)
    reply = json.loads(await t.handle_line(json.dumps(rpc("tools/list"))))
    assert "tools" in reply["result"]


async def test_run_reads_until_eof_and_writes_one_line_per_request(gateway):
    lines = [
        json.dumps(rpc("initialize", {"protocolVersion": "2025-03-26"}, id_=1)),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        "not json at all",
        json.dumps(rpc("tools/call", {"name": "echo", "arguments": {"text": "x"}}, id_=2)),
    ]
    stdin = io.StringIO("\n".join(lines) + "\n")
    stdout = io.StringIO()
    await StdioTransport(gateway.dispatcher, api_key=KEY_A, stdin=stdin, stdout=stdout).run()
    out = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [o.get("id") for o in out] == [1, None, 2]
    assert out[1]["error"]["code"] == -32700
    assert out[2]["result"]["structuredContent"] == {"text": "x"}


async def test_run_speaks_utf8_bytes_regardless_of_console_encoding(gateway):
    # The real console streams are byte buffers; non-ASCII must survive both ways.
    req = rpc("tools/call", {"name": "echo", "arguments": {"text": "héllo wörld ✓"}})
    stdin = io.BytesIO(json.dumps(req, ensure_ascii=False).encode("utf-8") + b"\n")
    stdout = io.BytesIO()
    await StdioTransport(gateway.dispatcher, api_key=KEY_A, stdin=stdin, stdout=stdout).run()
    reply = json.loads(stdout.getvalue().decode("utf-8"))
    assert reply["result"]["structuredContent"] == {"text": "héllo wörld ✓"}


def test_subprocess_server_round_trips_non_ascii_through_real_pipes():
    # PYTHONIOENCODING=cp1252 reproduces a stock Windows console; the server
    # must ignore it and speak UTF-8 on the pipe, as MCP clients do.
    root = Path(__file__).resolve().parent.parent
    server = (
        f"import sys; sys.path.insert(0, {str(root)!r})\n"
        "from mcp_gateway import Gateway\n"
        "from tests.conftest import echo, make_auth\n"
        "Gateway(tools=[echo], auth=make_auth()).serve_stdio()\n"
    )
    req = rpc("tools/call", {"name": "echo", "arguments": {"text": "Müller Ünal ✓"}})
    proc = subprocess.run(
        [sys.executable, "-c", server],
        input=json.dumps(req, ensure_ascii=False).encode("utf-8") + b"\n",
        capture_output=True,
        env={**os.environ, "MCP_GATEWAY_API_KEY": KEY_A, "PYTHONIOENCODING": "cp1252"},
        timeout=30,
        check=True,
    )
    reply = json.loads(proc.stdout.decode("utf-8"))
    assert reply["result"]["structuredContent"] == {"text": "Müller Ünal ✓"}
