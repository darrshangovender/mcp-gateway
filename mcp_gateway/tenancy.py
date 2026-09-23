"""Tenant isolation.

The gateway sets a ``TenantContext`` (a contextvar, so it is isolated per
task under concurrency) around every tool call. Tools read it through
``tenant_filter()`` when they touch data. After the call, ``assert_tenant_owned``
walks the result and raises if any row is tagged with a different tenant —
a second line of defence for the tool that forgot the filter.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from .protocol import TENANT_VIOLATION, GatewayError

_current_tenant: ContextVar[str | None] = ContextVar("mcp_gateway_tenant", default=None)

TENANT_KEY = "tenant_id"


class TenantContextError(GatewayError):
    """A tool tried to access data with no tenant bound to the call."""

    code = TENANT_VIOLATION


class TenantViolation(GatewayError):
    """A tool result carried rows belonging to another tenant."""

    code = TENANT_VIOLATION


class TenantContext:
    """Bind a tenant for the duration of a ``with`` block."""

    def __init__(self, tenant_id: str) -> None:
        if not tenant_id:
            raise ValueError("tenant_id must not be empty")
        self.tenant_id = tenant_id
        self._token: Token[str | None] | None = None

    def __enter__(self) -> str:
        self._token = _current_tenant.set(self.tenant_id)
        return self.tenant_id

    def __exit__(self, *exc: object) -> None:
        if self._token is not None:
            _current_tenant.reset(self._token)
            self._token = None

    @staticmethod
    def get() -> str | None:
        return _current_tenant.get()

    @staticmethod
    def current() -> str:
        return current_tenant()


def current_tenant() -> str:
    tenant = _current_tenant.get()
    if tenant is None:
        raise TenantContextError("no tenant bound to the current call")
    return tenant


@dataclass(frozen=True)
class TenantFilter:
    """A ready-to-use predicate for the current tenant.

    ``sql`` and ``params`` slot straight into a DB-API query; ``matches`` does
    the same job for in-memory rows.
    """

    tenant_id: str
    column: str = TENANT_KEY

    @property
    def sql(self) -> str:
        return f"{self.column} = ?"

    @property
    def params(self) -> tuple[str]:
        return (self.tenant_id,)

    def matches(self, row: Any) -> bool:
        if isinstance(row, BaseModel):
            row = row.model_dump()
        if isinstance(row, dict):
            return row.get(self.column) == self.tenant_id
        return getattr(row, self.column, None) == self.tenant_id


def tenant_filter(column: str = TENANT_KEY) -> TenantFilter:
    """The filter tools MUST apply to data access. Raises if no tenant is bound."""
    return TenantFilter(tenant_id=current_tenant(), column=column)


def assert_tenant_owned(result: Any, tenant_id: str | None = None, key: str = TENANT_KEY) -> Any:
    """Raise ``TenantViolation`` if any nested row is tagged with a foreign tenant.

    Rows without a ``tenant_id`` key are ignored: the check catches leaks, it
    does not force every payload to be tagged.
    """
    expected = tenant_id or current_tenant()
    foreign = _find_foreign(result, expected, key, path="$")
    if foreign:
        raise TenantViolation(
            f"result contains rows owned by tenant '{foreign[0][1]}'",
            data={"paths": [p for p, _ in foreign][:10], "expected_tenant": expected},
        )
    return result


def _find_foreign(node: Any, expected: str, key: str, path: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    if isinstance(node, BaseModel):
        node = node.model_dump()
    if isinstance(node, dict):
        tag = node.get(key)
        if isinstance(tag, str) and tag != expected:
            hits.append((path, tag))
        for k, v in node.items():
            hits.extend(_find_foreign(v, expected, key, f"{path}.{k}"))
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            hits.extend(_find_foreign(v, expected, key, f"{path}[{i}]"))
    return hits
