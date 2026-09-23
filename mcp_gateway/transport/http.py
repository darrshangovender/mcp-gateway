"""Starlette app: ``POST /mcp`` for JSON-RPC and ``GET /mcp/events`` for SSE.

Both share the gateway's dispatcher. The API key comes from
``Authorization: Bearer <key>`` or ``X-API-Key``. The SSE stream is
per-tenant: it authenticates the key, then relays only that tenant's
``tool_call`` events, preceded by the ``endpoint`` event MCP clients expect.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from typing import TYPE_CHECKING, Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from ..auth import AuthError
from ..events import CLOSE, Event
from ..protocol import AUTH_DENIED, INVALID_REQUEST, RequestContext, error_response

if TYPE_CHECKING:
    from ..server import Gateway

MCP_PATH = "/mcp"
EVENTS_PATH = "/mcp/events"
DEFAULT_MAX_BODY_BYTES = 1024 * 1024


async def read_body(request: Request, limit: int) -> bytes | None:
    """Read the body, giving up (``None``) as soon as it exceeds ``limit`` bytes.

    Per-tool payload caps only apply after the JSON has been parsed; this is
    the transport-level cap that stops a client from feeding the parser
    gigabytes first.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def extract_api_key(headers: Mapping[str, str]) -> str | None:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return headers.get("x-api-key") or None


def format_sse(event: str, data: str) -> str:
    lines = "".join(f"data: {chunk}\n" for chunk in data.splitlines() or [""])
    return f"event: {event}\n{lines}\n"


def create_app(
    gateway: Gateway,
    *,
    keepalive_seconds: float = 15.0,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Starlette:
    dispatcher = gateway.dispatcher

    async def mcp_post(request: Request) -> Response:
        body = await read_body(request, max_body_bytes)
        if body is None:
            return JSONResponse(
                error_response(
                    None,
                    INVALID_REQUEST,
                    f"request body exceeds {max_body_bytes} bytes",
                    {"reason": "body_too_large", "limit": max_body_bytes},
                ),
                status_code=413,
            )
        ctx = RequestContext(api_key=extract_api_key(request.headers), transport="http")
        reply = await dispatcher.dispatch_raw(body, ctx)
        if reply is None:
            return Response(status_code=202)
        return Response(reply, media_type="application/json")

    async def mcp_events(request: Request) -> Response:
        try:
            principal = gateway.auth.authenticate(extract_api_key(request.headers))
        except AuthError as exc:
            return JSONResponse(
                error_response(None, AUTH_DENIED, exc.message), status_code=401
            )

        async def stream() -> AsyncIterator[str]:
            yield format_sse("endpoint", MCP_PATH)
            with gateway.events.subscribe(principal.tenant_id) as queue:
                while not gateway.events.closed:
                    if await request.is_disconnected():
                        break
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=keepalive_seconds)
                    except TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    if item is CLOSE:
                        break
                    if isinstance(item, Event):
                        yield format_sse(item.event, json.dumps(item.data, default=str))

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    async def healthz(request: Request) -> Response:
        payload: dict[str, Any] = {
            "status": "ok",
            "server": gateway.info.model_dump(),
            "tools": sorted(gateway.registry.tools),
        }
        degraded = getattr(gateway.limiter, "degraded", False)
        if degraded:
            payload["ratelimit"] = {
                "degraded": True,
                "reason": getattr(gateway.limiter, "degraded_reason", None),
            }
        return JSONResponse(payload)

    return Starlette(
        routes=[
            Route(MCP_PATH, mcp_post, methods=["POST"]),
            Route(EVENTS_PATH, mcp_events, methods=["GET"]),
            Route("/healthz", healthz, methods=["GET"]),
        ]
    )
