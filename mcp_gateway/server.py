"""The ``Gateway``: wires auth, tenancy, guardrails, rate limiting, audit and
telemetry around a registry of tools, and exposes the result over stdio
or ASGI.

Order of the ``tools/call`` pipeline, which the README diagram mirrors:

    authenticate -> scope check -> rate limit -> guardrail input checks
    -> bind tenant -> invoke tool -> tenant ownership check -> PII scrub
    -> audit (always, on every outcome)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from .audit import AuditLog, AuditRecord, MemoryAuditLog, hash_args
from .auth import Authenticator, Principal, require_scope
from .events import Event, EventHub
from .guardrails import check_input, scrub_pii, scrub_text
from .protocol import (
    DENIAL_CODES,
    INTERNAL_ERROR,
    PROTOCOL_VERSION,
    Dispatcher,
    GatewayError,
    Implementation,
    InitializeParams,
    InitializeResult,
    InvalidParams,
    PromptMessage,
    PromptsGetParams,
    PromptsGetResult,
    PromptsListResult,
    RequestContext,
    ResourceContents,
    ResourcesListResult,
    ResourcesReadParams,
    ResourcesReadResult,
    TextContent,
    ToolsCallParams,
    ToolsCallResult,
    ToolsListResult,
    parse_params,
)
from .ratelimit import MemoryRateLimiter, RateLimiter
from .registry import Registry, ToolSpec
from .telemetry import NoopTracer, Tracer
from .tenancy import TenantContext, TenantViolation, assert_tenant_owned

logger = logging.getLogger("mcp_gateway")

SCOPE_TOOLS_CALL = "tools:call"
SCOPE_TOOLS_LIST = "tools:list"
SCOPE_RESOURCES_READ = "resources:read"
SCOPE_PROMPTS_READ = "prompts:read"


@dataclass(frozen=True)
class CallContext:
    """What a tool handler receives alongside its validated arguments."""

    principal: Principal
    tenant_id: str
    tool: str
    request_id: int | str | None = None
    transport: str = "unknown"


class Gateway:
    def __init__(
        self,
        tools: Iterable[Any] = (),
        *,
        auth: Authenticator,
        resources: Iterable[Any] = (),
        prompts: Iterable[Any] = (),
        limiter: RateLimiter | None = None,
        audit: AuditLog | None = None,
        tracer: Tracer | None = None,
        name: str = "mcp-gateway",
        version: str = "0.1.0",
        instructions: str | None = None,
    ) -> None:
        self.registry = Registry([*tools, *resources, *prompts])
        self.auth = auth
        self.limiter: RateLimiter = limiter or MemoryRateLimiter()
        self.audit: AuditLog = audit or MemoryAuditLog()
        self.tracer: Tracer = tracer or NoopTracer()
        self.events = EventHub()
        self.info = Implementation(name=name, version=version)
        self.instructions = instructions
        self.dispatcher = Dispatcher()
        self._register_methods()

    # --- wiring -----------------------------------------------------------

    def _register_methods(self) -> None:
        d = self.dispatcher
        d.register("initialize", self._initialize)
        d.register("notifications/initialized", self._noop)
        d.register("ping", self._ping)
        d.register("tools/list", self._tools_list)
        d.register("tools/call", self._tools_call)
        d.register("resources/list", self._resources_list)
        d.register("resources/read", self._resources_read)
        d.register("prompts/list", self._prompts_list)
        d.register("prompts/get", self._prompts_get)

    def _principal(self, ctx: RequestContext) -> Principal:
        if ctx.principal is None:
            ctx.principal = self.auth.authenticate(ctx.api_key)
        return ctx.principal

    # --- session methods --------------------------------------------------

    async def _initialize(self, params: dict[str, Any] | None, ctx: RequestContext) -> Any:
        parse_params(InitializeParams, params)
        return InitializeResult(
            protocolVersion=PROTOCOL_VERSION,
            serverInfo=self.info,
            instructions=self.instructions,
        )

    async def _noop(self, params: dict[str, Any] | None, ctx: RequestContext) -> None:
        return None

    async def _ping(self, params: dict[str, Any] | None, ctx: RequestContext) -> dict[str, Any]:
        return {}

    # --- listing methods --------------------------------------------------

    async def _tools_list(self, params: dict[str, Any] | None, ctx: RequestContext) -> Any:
        principal = self._principal(ctx)
        require_scope(principal, SCOPE_TOOLS_LIST)
        visible = [
            spec.definition()
            for spec in self.registry.tools.values()
            if all(principal.has_scope(s) for s in spec.scopes)
        ]
        return ToolsListResult(tools=visible)

    async def _resources_list(self, params: dict[str, Any] | None, ctx: RequestContext) -> Any:
        principal = self._principal(ctx)
        require_scope(principal, SCOPE_RESOURCES_READ)
        return ResourcesListResult(resources=self.registry.resource_definitions())

    async def _resources_read(self, params: dict[str, Any] | None, ctx: RequestContext) -> Any:
        principal = self._principal(ctx)
        require_scope(principal, SCOPE_RESOURCES_READ)
        p = parse_params(ResourcesReadParams, params)
        spec = self.registry.resources.get(p.uri)
        if spec is None:
            raise InvalidParams(f"unknown resource: {p.uri}", data={"uri": p.uri})
        call_ctx = CallContext(
            principal=principal, tenant_id=principal.tenant_id, tool=f"resource:{p.uri}",
            request_id=ctx.request_id, transport=ctx.transport,
        )
        with TenantContext(principal.tenant_id):
            text = await spec.read(call_ctx)
        text = scrub_pii(text if isinstance(text, str) else json.dumps(text, default=str))
        return ResourcesReadResult(
            contents=[ResourceContents(uri=p.uri, mimeType=spec.mime_type, text=text)]
        )

    async def _prompts_list(self, params: dict[str, Any] | None, ctx: RequestContext) -> Any:
        principal = self._principal(ctx)
        require_scope(principal, SCOPE_PROMPTS_READ)
        return PromptsListResult(prompts=self.registry.prompt_definitions())

    async def _prompts_get(self, params: dict[str, Any] | None, ctx: RequestContext) -> Any:
        principal = self._principal(ctx)
        require_scope(principal, SCOPE_PROMPTS_READ)
        p = parse_params(PromptsGetParams, params)
        spec = self.registry.prompts.get(p.name)
        if spec is None:
            raise InvalidParams(f"unknown prompt: {p.name}", data={"name": p.name})
        missing = [a.name for a in spec.arguments if a.required and a.name not in p.arguments]
        if missing:
            raise InvalidParams(f"missing prompt arguments: {', '.join(missing)}")
        call_ctx = CallContext(
            principal=principal, tenant_id=principal.tenant_id, tool=f"prompt:{p.name}",
            request_id=ctx.request_id, transport=ctx.transport,
        )
        with TenantContext(principal.tenant_id):
            rendered = await spec.render(p.arguments, call_ctx)
        if isinstance(rendered, str):
            messages = [PromptMessage(content=TextContent(text=rendered))]
        else:
            messages = [PromptMessage.model_validate(m) for m in rendered]
        # Prompts render data the same way tools return it; scrub them the same way.
        messages = [PromptMessage.model_validate(scrub_pii(m)) for m in messages]
        return PromptsGetResult(description=spec.description, messages=messages)

    # --- the guarded call -------------------------------------------------

    async def _tools_call(self, params: dict[str, Any] | None, ctx: RequestContext) -> Any:
        started = time.perf_counter()
        # The record exists before anything can fail, so a malformed call is
        # audited like every other outcome rather than slipping past the log.
        requested = params.get("name") if isinstance(params, dict) else None
        record = AuditRecord(
            request_id=ctx.request_id,
            transport=ctx.transport,
            method="tools/call",
            tool=requested if isinstance(requested, str) else None,
            outcome="ok",
        )
        principal: Principal | None = None
        with self.tracer.span("mcp.tools/call", transport=ctx.transport) as span:
            try:
                call = parse_params(ToolsCallParams, params)
                record.tool = call.name
                record.args_hash = hash_args(call.arguments)
                span.set_attribute("tool", call.name)

                principal = self._principal(ctx)
                record.tenant_id = principal.tenant_id
                record.key_id = principal.key_id
                span.set_attribute("tenant_id", principal.tenant_id)

                spec = self.registry.tools.get(call.name)
                if spec is None:
                    raise InvalidParams(f"unknown tool: {call.name}", data={"tool": call.name})

                require_scope(principal, SCOPE_TOOLS_CALL, *spec.scopes)

                tier = principal.rate_tier or spec.rate_tier or self.limiter.default_tier
                decision = await self.limiter.acquire(principal.tenant_id, spec.name, tier)
                span.set_attribute("rate_tier", decision.tier)
                decision.raise_if_denied(principal.tenant_id, spec.name)

                check_input(spec.policy, spec.name, call.arguments, principal)
                args = parse_params(spec.input_model, call.arguments)

                call_ctx = CallContext(
                    principal=principal, tenant_id=principal.tenant_id, tool=spec.name,
                    request_id=ctx.request_id, transport=ctx.transport,
                )
                with TenantContext(principal.tenant_id):
                    try:
                        raw = await spec.invoke(args, call_ctx)
                    except GatewayError:
                        raise
                    except Exception as exc:  # noqa: BLE001 - tool failure is a result
                        record.outcome = "error"
                        # Exception text is tool-authored and may quote the row it
                        # choked on; the audit log gets it scrubbed like any output.
                        record.denial_reason = scrub_text(f"{exc.__class__.__name__}: {exc}")
                        span.record_error(record.denial_reason, exc)
                        return ToolsCallResult(
                            content=[TextContent(text=f"tool error: {exc.__class__.__name__}")],
                            isError=True,
                        )
                    payload = self._shape_output(spec, raw)
                    assert_tenant_owned(payload, principal.tenant_id)

                if spec.policy.scrub_output:
                    payload = scrub_pii(payload)
                structured = payload if isinstance(payload, dict) else None
                return ToolsCallResult(
                    content=[TextContent(text=json.dumps(payload, default=str))],
                    structuredContent=structured,
                )
            except GatewayError as exc:
                record.error_code = exc.code
                record.outcome = "denied" if exc.code in DENIAL_CODES else "error"
                record.denial_reason = exc.message
                span.record_error(exc.message, exc)
                if isinstance(exc, TenantViolation):
                    # The audit log keeps which tenant's rows leaked and where;
                    # the client learns only that the call was blocked.
                    raise TenantViolation(
                        f"result of '{record.tool}' failed the tenant ownership check",
                        data={"reason": "tenant_violation", "tool": record.tool},
                    ) from None
                raise
            except Exception as exc:  # never leak, always audit
                record.error_code = INTERNAL_ERROR
                record.outcome = "error"
                record.denial_reason = exc.__class__.__name__
                span.record_error(record.denial_reason, exc)
                logger.exception("unhandled error in tools/call for %r", record.tool)
                raise GatewayError("internal error") from exc
            finally:
                record.latency_ms = round((time.perf_counter() - started) * 1000, 3)
                self.audit.write(record)
                self.events.publish(
                    Event(
                        event="tool_call",
                        tenant_id=record.tenant_id,
                        data={
                            "tool": record.tool,
                            "outcome": record.outcome,
                            "error_code": record.error_code,
                            "latency_ms": record.latency_ms,
                            "request_id": record.request_id,
                        },
                    )
                )

    @staticmethod
    def _shape_output(spec: ToolSpec, raw: Any) -> Any:
        """Validate against the output model when one is declared; return JSON-able data."""
        if spec.output_model is not None:
            try:
                model = (
                    raw if isinstance(raw, spec.output_model)
                    else spec.output_model.model_validate(raw)
                )
            except ValidationError as exc:
                raise GatewayError(
                    f"tool '{spec.name}' returned data that does not match its output model",
                    data={"errors": [e["msg"] for e in exc.errors()][:5]},
                ) from exc
            return model.model_dump(mode="json")
        if isinstance(raw, BaseModel):
            return raw.model_dump(mode="json")
        return raw

    # --- transports -------------------------------------------------------

    def asgi(self, **options: Any) -> Any:
        """Starlette app; ``options`` (``max_body_bytes``, ``keepalive_seconds``) go to it."""
        from .transport.http import create_app  # lazy: keeps starlette off the stdio path

        return create_app(self, **options)

    async def run_stdio(self, *, api_key: str | None = None) -> None:
        from .transport.stdio import StdioTransport

        await StdioTransport(self.dispatcher, api_key=api_key).run()

    def serve_stdio(self, *, api_key: str | None = None) -> None:
        asyncio.run(self.run_stdio(api_key=api_key))
