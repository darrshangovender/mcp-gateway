"""mcp-gateway: a hardened MCP server framework.

Tenant isolation, per-tool auth and guardrails, rate limiting, audit logging
and telemetry around the tools you expose to LLM clients.
"""

from .audit import AuditRecord, JSONLAuditLog, MemoryAuditLog, NullAuditLog, hash_args
from .auth import APIKeyAuth, AuthError, KeyRecord, Principal, generate_key, hash_key, require_scope
from .guardrails import GuardrailDenied, ToolPolicy, scrub_pii
from .protocol import (
    AUTH_DENIED,
    GUARDRAIL_DENIED,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    PROTOCOL_VERSION,
    RATE_LIMITED,
    TENANT_VIOLATION,
    Dispatcher,
    GatewayError,
    PromptArgument,
    RequestContext,
)
from .ratelimit import MemoryRateLimiter, RateLimited, RedisRateLimiter, Tier
from .registry import Registry, prompt, resource, tool
from .server import CallContext, Gateway
from .telemetry import NoopTracer, RecordingTracer, get_tracer
from .tenancy import TenantContext, TenantViolation, assert_tenant_owned, tenant_filter

__version__ = "0.1.0"

__all__ = [
    "AUTH_DENIED",
    "GUARDRAIL_DENIED",
    "INVALID_PARAMS",
    "METHOD_NOT_FOUND",
    "PROTOCOL_VERSION",
    "RATE_LIMITED",
    "TENANT_VIOLATION",
    "APIKeyAuth",
    "AuditRecord",
    "AuthError",
    "CallContext",
    "Dispatcher",
    "Gateway",
    "GatewayError",
    "GuardrailDenied",
    "JSONLAuditLog",
    "KeyRecord",
    "MemoryAuditLog",
    "MemoryRateLimiter",
    "NoopTracer",
    "NullAuditLog",
    "Principal",
    "PromptArgument",
    "RateLimited",
    "RecordingTracer",
    "RedisRateLimiter",
    "Registry",
    "RequestContext",
    "TenantContext",
    "TenantViolation",
    "Tier",
    "ToolPolicy",
    "assert_tenant_owned",
    "generate_key",
    "get_tracer",
    "hash_args",
    "hash_key",
    "prompt",
    "require_scope",
    "resource",
    "scrub_pii",
    "tenant_filter",
    "tool",
]
