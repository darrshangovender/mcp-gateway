"""JSON-RPC 2.0 envelope, MCP method models, and the method dispatcher.

Everything on the wire is a pydantic model. The dispatcher maps a method name
to a handler and turns every failure mode into the correct JSON-RPC error
code, so transports (stdio, HTTP) only move bytes and never interpret them.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger("mcp_gateway")

PROTOCOL_VERSION = "2025-03-26"

# --- JSON-RPC 2.0 reserved codes -------------------------------------------
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# --- Gateway codes (the -32000..-32099 implementation-defined range) --------
GUARDRAIL_DENIED = -32001
AUTH_DENIED = -32002
RATE_LIMITED = -32003
TENANT_VIOLATION = -32004

DENIAL_CODES = frozenset({GUARDRAIL_DENIED, AUTH_DENIED, RATE_LIMITED, TENANT_VIOLATION})


class GatewayError(Exception):
    """Base for every error the gateway raises deliberately.

    Subclasses set ``code``; the dispatcher turns the exception into a
    JSON-RPC error object without leaking a stack trace to the client.
    """

    code: int = INTERNAL_ERROR

    def __init__(self, message: str, *, code: int | None = None, data: Any = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.data = data

    def to_error(self) -> JSONRPCError:
        return JSONRPCError(code=self.code, message=self.message, data=self.data)


class InvalidParams(GatewayError):
    code = INVALID_PARAMS


class MethodNotFound(GatewayError):
    code = METHOD_NOT_FOUND


# --- JSON-RPC envelope -----------------------------------------------------

RequestId = int | str | None


class JSONRPCRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    jsonrpc: Literal["2.0"]
    id: RequestId = None
    method: str = Field(min_length=1)
    params: dict[str, Any] | None = None

    @property
    def is_notification(self) -> bool:
        """A request without an ``id`` member is a notification: no response."""
        return "id" not in self.model_fields_set


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Any | None = None


class JSONRPCResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: RequestId = None
    result: Any | None = None
    error: JSONRPCError | None = None

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self.id}
        if self.error is not None:
            body["error"] = self.error.model_dump(exclude_none=True)
        else:
            body["result"] = self.result
        return body


def error_response(id_: RequestId, code: int, message: str, data: Any = None) -> dict[str, Any]:
    return JSONRPCResponse(id=id_, error=JSONRPCError(code=code, message=message, data=data)).to_dict()


# --- MCP method models -----------------------------------------------------


class Implementation(BaseModel):
    name: str
    version: str


class InitializeParams(BaseModel):
    model_config = ConfigDict(extra="ignore")

    protocolVersion: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    clientInfo: Implementation | None = None


class ServerCapabilities(BaseModel):
    tools: dict[str, Any] = Field(default_factory=lambda: {"listChanged": False})
    resources: dict[str, Any] = Field(default_factory=dict)
    prompts: dict[str, Any] = Field(default_factory=dict)


class InitializeResult(BaseModel):
    protocolVersion: str = PROTOCOL_VERSION
    capabilities: ServerCapabilities = Field(default_factory=ServerCapabilities)
    serverInfo: Implementation
    instructions: str | None = None


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    inputSchema: dict[str, Any]


class ToolsListResult(BaseModel):
    tools: list[ToolDefinition]


class ToolsCallParams(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class TextContent(BaseModel):
    type: Literal["text"] = "text"
    text: str


class ToolsCallResult(BaseModel):
    content: list[TextContent]
    structuredContent: dict[str, Any] | None = None
    isError: bool = False


class ResourceDefinition(BaseModel):
    uri: str
    name: str
    description: str | None = None
    mimeType: str = "text/plain"


class ResourcesListResult(BaseModel):
    resources: list[ResourceDefinition]


class ResourcesReadParams(BaseModel):
    model_config = ConfigDict(extra="ignore")

    uri: str = Field(min_length=1)


class ResourceContents(BaseModel):
    uri: str
    mimeType: str = "text/plain"
    text: str


class ResourcesReadResult(BaseModel):
    contents: list[ResourceContents]


class PromptArgument(BaseModel):
    name: str
    description: str | None = None
    required: bool = False


class PromptDefinition(BaseModel):
    name: str
    description: str | None = None
    arguments: list[PromptArgument] = Field(default_factory=list)


class PromptsListResult(BaseModel):
    prompts: list[PromptDefinition]


class PromptsGetParams(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(min_length=1)
    arguments: dict[str, str] = Field(default_factory=dict)


class PromptMessage(BaseModel):
    role: Literal["user", "assistant"] = "user"
    content: TextContent


class PromptsGetResult(BaseModel):
    description: str | None = None
    messages: list[PromptMessage]


def parse_params(model: type[BaseModel], params: dict[str, Any] | None) -> Any:
    """Validate ``params`` against ``model``; raise ``InvalidParams`` (-32602) on failure."""
    try:
        return model.model_validate(params or {})
    except ValidationError as exc:
        raise InvalidParams(
            f"invalid params for {model.__name__}",
            data={"errors": _compact_errors(exc)},
        ) from exc


def _compact_errors(exc: ValidationError) -> list[dict[str, Any]]:
    return [
        {"loc": [str(p) for p in e["loc"]], "msg": e["msg"], "type": e["type"]}
        for e in exc.errors()
    ]


# --- Dispatcher ------------------------------------------------------------


@dataclass
class RequestContext:
    """What a transport knows about the caller before any auth has run."""

    api_key: str | None = None
    transport: str = "unknown"
    request_id: RequestId = None
    principal: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


Handler = Callable[[dict[str, Any] | None, RequestContext], Awaitable[Any] | Any]


class Dispatcher:
    """Route a JSON-RPC message to its handler and shape the reply.

    Handlers receive ``(params, context)`` and return a pydantic model or a
    plain dict. Any ``GatewayError`` becomes an error object with that error's
    code; an unexpected exception becomes -32603 with no traceback attached.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {}

    def register(self, method: str, handler: Handler) -> None:
        self._handlers[method] = handler

    def method(self, name: str) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            self.register(name, fn)
            return fn

        return deco

    @property
    def methods(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))

    async def dispatch_raw(self, raw: str | bytes, ctx: RequestContext) -> str | None:
        """Parse one line/body of JSON, dispatch it, and serialise the reply."""
        try:
            message = json.loads(raw)
        except (ValueError, TypeError):
            return json.dumps(error_response(None, PARSE_ERROR, "parse error"))
        reply = await self.dispatch(message, ctx)
        return None if reply is None else json.dumps(reply, default=str)

    async def dispatch(
        self, message: Any, ctx: RequestContext
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        if isinstance(message, list):
            if not message:
                return error_response(None, INVALID_REQUEST, "empty batch")
            replies = [await self._dispatch_one(m, ctx) for m in message]
            out = [r for r in replies if r is not None]
            return out or None
        return await self._dispatch_one(message, ctx)

    async def _dispatch_one(self, message: Any, ctx: RequestContext) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return error_response(None, INVALID_REQUEST, "request must be a JSON object")
        try:
            request = JSONRPCRequest.model_validate(message)
        except ValidationError as exc:
            id_ = message.get("id") if isinstance(message.get("id"), (int, str)) else None
            return error_response(
                id_, INVALID_REQUEST, "invalid request", {"errors": _compact_errors(exc)}
            )

        ctx.request_id = request.id
        handler = self._handlers.get(request.method)
        if handler is None:
            if request.is_notification:
                return None
            return error_response(
                request.id, METHOD_NOT_FOUND, f"method not found: {request.method}"
            )

        try:
            result = handler(request.params, ctx)
            if inspect.isawaitable(result):
                result = await result
        except GatewayError as exc:
            if request.is_notification:
                return None
            return JSONRPCResponse(id=request.id, error=exc.to_error()).to_dict()
        except ValidationError as exc:
            if request.is_notification:
                return None
            return error_response(
                request.id, INVALID_PARAMS, "invalid params", {"errors": _compact_errors(exc)}
            )
        except Exception:  # deliberate boundary: never leak tracebacks
            # The client gets a bare -32603; the traceback goes to the server log
            # so the failure is not silent on both sides.
            logger.exception("unhandled error in handler for %r", request.method)
            if request.is_notification:
                return None
            return error_response(request.id, INTERNAL_ERROR, "internal error")

        if request.is_notification:
            return None
        if isinstance(result, BaseModel):
            result = result.model_dump(mode="json", exclude_none=True)
        return JSONRPCResponse(id=request.id, result=result).to_dict()
