"""A minimal stdio MCP client: spawn crm_server.py and drive it end to end.

    python examples/client_demo.py

This is what Claude Desktop or an IDE does, minus the model in the middle:
initialize -> notifications/initialized -> tools/list -> tools/call.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

SERVER = Path(__file__).resolve().parent / "crm_server.py"


class StdioClient:
    def __init__(self, api_key: str) -> None:
        env = {**os.environ, "MCP_GATEWAY_API_KEY": api_key, "PYTHONUNBUFFERED": "1"}
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER), "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit: a server traceback should be visible, not swallowed
            env=env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._next_id = 0

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self.proc.stdin and self.proc.stdout
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed the pipe")
        return json.loads(line)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        assert self.proc.stdin
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        assert self.proc.stdin
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def main() -> None:
    client = StdioClient(api_key=os.environ.get("CRM_ACME_KEY", "demo-acme-key"))
    try:
        init = client.request("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "client_demo", "version": "0.1.0"},
        })
        info = init["result"]["serverInfo"]
        print(f"initialize     -> {info['name']} {info['version']} "
              f"(protocol {init['result']['protocolVersion']})")
        client.notify("notifications/initialized")

        tools = client.request("tools/list")
        names = [t["name"] for t in tools["result"]["tools"]]
        print(f"tools/list     -> {', '.join(names)}")

        r = client.request("tools/call", {"name": "search_customers", "arguments": {"query": "a"}})
        customers = r["result"]["structuredContent"]["customers"]
        print(f"tools/call     -> search_customers returned {len(customers)} rows")
        for c in customers:
            print(f"                  {c['name']:<22} {c['email']:<9} {c['phone']}")

        r = client.request("tools/call", {"name": "get_customer", "arguments": {"customer_id": 5}})
        print(f"tools/call     -> get_customer(5, owned by globex): "
              f"isError={r['result'].get('isError')} {r['result']['content'][0]['text']}")

        r = client.request("tools/call", {"name": "nonexistent", "arguments": {}})
        print(f"tools/call     -> unknown tool: error code {r['error']['code']}")

        r = client.request("no/such/method")
        print(f"no/such/method -> error code {r['error']['code']}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
