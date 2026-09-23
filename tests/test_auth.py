"""Auth: missing key, wrong key, insufficient scope, hashing, revocation."""

from __future__ import annotations

import pytest

from mcp_gateway import AUTH_DENIED, APIKeyAuth, AuthError, Principal, hash_key, require_scope
from mcp_gateway.auth import KeyRecord, generate_key
from tests.conftest import KEY_A, KEY_READONLY, call, call_tool, make_auth


def test_keys_are_stored_hashed_not_raw():
    auth = make_auth()
    stored = [r.key_hash for r in auth._records]
    assert KEY_A not in stored
    assert hash_key(KEY_A, "test-salt") in stored
    assert hash_key(KEY_A, "test-salt") != hash_key(KEY_A, "other-salt")


def test_authenticate_resolves_principal():
    p = make_auth().authenticate(KEY_A)
    assert p.tenant_id == "tenant-a"
    assert p.key_id == "a-1"
    assert p.has_scope("tools:call")
    assert not p.has_scope("admin")


def test_missing_key_raises():
    with pytest.raises(AuthError, match="missing"):
        make_auth().authenticate(None)
    with pytest.raises(AuthError, match="missing"):
        make_auth().authenticate("")


def test_wrong_key_raises():
    with pytest.raises(AuthError, match="invalid") as exc:
        make_auth().authenticate("not-a-real-key")
    assert exc.value.code == AUTH_DENIED


def test_revoked_key_is_rejected():
    auth = make_auth()
    assert auth.revoke("a-1")
    assert not auth.revoke("a-1")
    with pytest.raises(AuthError):
        auth.authenticate(KEY_A)
    assert len(auth) == 2


def test_wildcard_scope_grants_everything():
    p = Principal(tenant_id="t", scopes=frozenset({"*"}))
    require_scope(p, "tools:call", "anything:at:all")


def test_require_scope_reports_missing_scope():
    p = Principal(tenant_id="t", scopes=frozenset({"tools:call"}))
    with pytest.raises(AuthError) as exc:
        require_scope(p, "tools:call", "notes:write")
    assert "notes:write" in exc.value.message
    assert exc.value.data["required"] == ["tools:call", "notes:write"]


def test_records_can_be_loaded_pre_hashed():
    rec = KeyRecord(key_id="k", key_hash=hash_key("raw", "s"), tenant_id="t", scopes=["x"])
    auth = APIKeyAuth(salt="s", records=[rec])
    assert auth.authenticate("raw").tenant_id == "t"


def test_empty_salt_rejected():
    with pytest.raises(ValueError):
        APIKeyAuth(salt="")


def test_generate_key_is_unique_and_prefixed():
    a, b = generate_key(), generate_key()
    assert a != b and a.startswith("mgk_")


async def test_tools_call_without_key_is_denied(gateway):
    reply = await call_tool(gateway, None, "echo", {"text": "x"})
    assert reply["error"]["code"] == AUTH_DENIED
    assert "missing" in reply["error"]["message"]


async def test_tools_call_with_wrong_key_is_denied(gateway):
    reply = await call_tool(gateway, "bogus", "echo", {"text": "x"})
    assert reply["error"]["code"] == AUTH_DENIED


async def test_insufficient_scope_is_denied(gateway):
    reply = await call_tool(gateway, KEY_READONLY, "echo", {"text": "x"})
    assert reply["error"]["code"] == AUTH_DENIED
    assert "tools:call" in reply["error"]["message"]


async def test_tool_specific_scope_is_enforced(gateway, audit):
    # tenant-a's readonly key has tools:list only; list_rows also needs rows:read
    reply = await call_tool(gateway, KEY_READONLY, "list_rows")
    assert reply["error"]["code"] == AUTH_DENIED
    assert audit.records[-1].outcome == "denied"


async def test_tools_list_hides_tools_the_principal_cannot_call(gateway):
    reply = await call(gateway, KEY_READONLY, "tools/list")
    names = {t["name"] for t in reply["result"]["tools"]}
    assert "echo" in names
    assert "list_rows" not in names


async def test_listing_methods_require_auth(gateway):
    for method in ("tools/list", "resources/list", "prompts/list"):
        reply = await call(gateway, None, method)
        assert reply["error"]["code"] == AUTH_DENIED, method
