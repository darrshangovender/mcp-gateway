"""API-key authentication resolving to a ``Principal``.

Keys are never stored raw: the store holds ``sha256(salt : key)`` and
comparisons run in constant time. A principal carries the tenant it belongs
to, the scopes it may exercise, and the rate tier it is billed at.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, Field

from .protocol import AUTH_DENIED, GatewayError

WILDCARD_SCOPE = "*"


class AuthError(GatewayError):
    code = AUTH_DENIED


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    scopes: frozenset[str] = frozenset()
    rate_tier: str | None = None
    key_id: str = ""

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or WILDCARD_SCOPE in self.scopes


class KeyRecord(BaseModel):
    """A hashed key as it would sit in config or a database row."""

    key_id: str
    key_hash: str
    tenant_id: str
    scopes: list[str] = Field(default_factory=list)
    rate_tier: str | None = None
    active: bool = True


def hash_key(raw_key: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{raw_key}".encode()).hexdigest()


def generate_key(prefix: str = "mgk") -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


class Authenticator(Protocol):
    def authenticate(self, api_key: str | None) -> Principal: ...


class APIKeyAuth:
    """In-memory store of hashed API keys.

    Lookups iterate every record with ``hmac.compare_digest`` rather than
    indexing by hash, so response time does not reveal whether a key exists.
    """

    def __init__(self, salt: str, records: Iterable[KeyRecord] = ()) -> None:
        if not salt:
            raise ValueError("salt must not be empty")
        self._salt = salt
        self._records: list[KeyRecord] = list(records)

    def add_key(
        self,
        raw_key: str,
        *,
        tenant_id: str,
        scopes: Iterable[str] = (),
        rate_tier: str | None = None,
        key_id: str | None = None,
    ) -> str:
        """Hash ``raw_key`` and store it; returns the key id."""
        kid = key_id or f"key_{secrets.token_hex(4)}"
        self._records.append(
            KeyRecord(
                key_id=kid,
                key_hash=hash_key(raw_key, self._salt),
                tenant_id=tenant_id,
                scopes=sorted(set(scopes)),
                rate_tier=rate_tier,
            )
        )
        return kid

    def revoke(self, key_id: str) -> bool:
        for rec in self._records:
            if rec.key_id == key_id and rec.active:
                rec.active = False
                return True
        return False

    def __len__(self) -> int:
        return sum(1 for r in self._records if r.active)

    def authenticate(self, api_key: str | None) -> Principal:
        if not api_key:
            raise AuthError("missing API key")
        digest = hash_key(api_key, self._salt)
        match: KeyRecord | None = None
        for rec in self._records:
            # Deliberately no early exit: the whole list is compared every time.
            if hmac.compare_digest(rec.key_hash, digest) and rec.active:
                match = rec
        if match is None:
            raise AuthError("invalid API key")
        return Principal(
            tenant_id=match.tenant_id,
            scopes=frozenset(match.scopes),
            rate_tier=match.rate_tier,
            key_id=match.key_id,
        )


def require_scope(principal: Principal, *scopes: str) -> None:
    """Raise ``AuthError`` (-32002) unless the principal holds every scope."""
    for scope in scopes:
        if not principal.has_scope(scope):
            raise AuthError(
                f"missing scope '{scope}'",
                data={"required": list(scopes), "tenant_id": principal.tenant_id},
            )
