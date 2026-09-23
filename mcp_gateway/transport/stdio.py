"""Newline-delimited JSON-RPC over stdin/stdout.

This is the transport Claude Desktop and most IDEs use: they spawn the
server as a subprocess and speak one JSON object per line. The API key
arrives through the environment (``MCP_GATEWAY_API_KEY``), which is how those
clients pass secrets to a subprocess.

The pipes are driven as raw bytes and decoded as UTF-8 here, because the
text wrappers on ``sys.stdin``/``sys.stdout`` follow the console code page
(cp1252 on a stock Windows box) and would mangle or reject non-ASCII input.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import IO, Any

from ..protocol import Dispatcher, RequestContext

API_KEY_ENV = "MCP_GATEWAY_API_KEY"


class StdioTransport:
    def __init__(
        self,
        dispatcher: Dispatcher,
        *,
        api_key: str | None = None,
        api_key_env: str = API_KEY_ENV,
        stdin: IO[Any] | None = None,
        stdout: IO[Any] | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.api_key = api_key if api_key is not None else os.environ.get(api_key_env)
        self._stdin = stdin
        self._stdout = stdout

    def context(self) -> RequestContext:
        return RequestContext(api_key=self.api_key, transport="stdio")

    async def handle_line(self, line: str | bytes) -> str | None:
        """Dispatch one line; returns the reply line (without newline) or None."""
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        line = line.strip()
        if not line:
            return None
        return await self.dispatcher.dispatch_raw(line, self.context())

    async def run(self) -> None:
        # Explicit streams are used as given (tests pass StringIO); the real
        # console streams are unwrapped to their byte buffers.
        stdin = self._stdin if self._stdin is not None else getattr(sys.stdin, "buffer", sys.stdin)
        stdout = (
            self._stdout if self._stdout is not None else getattr(sys.stdout, "buffer", sys.stdout)
        )
        loop = asyncio.get_running_loop()
        while True:
            # readline() blocks; keep it off the event loop so async tools run freely.
            line = await loop.run_in_executor(None, stdin.readline)
            if not line:
                break
            reply = await self.handle_line(line)
            if reply is not None:
                out = reply + "\n"
                stdout.write(out.encode("utf-8") if isinstance(line, bytes) else out)
                stdout.flush()
