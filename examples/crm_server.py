"""A realistic gateway over a SQLite "CRM" with two tenants.

    python examples/crm_server.py demo     # in-process walkthrough of the controls
    python examples/crm_server.py serve    # MCP server over stdio (what a client spawns)
    uvicorn examples.crm_server:app        # the same gateway over HTTP/SSE

Four tools: search_customers, get_customer, create_note, list_open_invoices.
Every row carries a tenant_id; every query goes through tenant_filter().
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
from typing import Any

from pydantic import BaseModel, Field

from mcp_gateway import (
    APIKeyAuth,
    CallContext,
    Gateway,
    JSONLAuditLog,
    MemoryAuditLog,
    MemoryRateLimiter,
    RedisRateLimiter,
    RequestContext,
    Tier,
    ToolPolicy,
    resource,
    tenant_filter,
    tool,
)

# --- the "CRM" -------------------------------------------------------------

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.row_factory = sqlite3.Row

SCHEMA = """
CREATE TABLE customers (
    id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    email TEXT NOT NULL, phone TEXT NOT NULL, id_number TEXT
);
CREATE TABLE notes (
    id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, customer_id INTEGER NOT NULL,
    body TEXT NOT NULL, author TEXT NOT NULL
);
CREATE TABLE invoices (
    id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, customer_id INTEGER NOT NULL,
    amount_zar REAL NOT NULL, status TEXT NOT NULL
);
"""

SEED_CUSTOMERS = [
    # id, tenant, name, email, phone, SA ID (valid Luhn check digit)
    (1, "acme", "Thandi Mkhize", "thandi@example.co.za", "082 123 4567", "9001015009086"),
    (2, "acme", "Pieter van der Merwe", "pieter@example.co.za", "+27 83 555 0199", None),
    (3, "acme", "Ayesha Naidoo", "ayesha@example.com", "031 555 0123", None),
    (4, "globex", "Sipho Dlamini", "sipho@globex.example", "072 987 6543", "8506155012089"),
    (5, "globex", "Lerato Molefe", "lerato@globex.example", "+27 84 000 1234", None),
]
SEED_INVOICES = [
    (1, "acme", 1, 12500.00, "open"),
    (2, "acme", 2, 3200.50, "paid"),
    (3, "acme", 3, 890.00, "open"),
    (4, "globex", 4, 45000.00, "open"),
    (5, "globex", 5, 150.00, "open"),
]


def seed() -> None:
    DB.executescript(SCHEMA)
    DB.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?)", SEED_CUSTOMERS)
    DB.executemany("INSERT INTO invoices VALUES (?,?,?,?,?)", SEED_INVOICES)
    DB.commit()


seed()


# --- models -----------------------------------------------------------------


class Customer(BaseModel):
    id: int
    tenant_id: str
    name: str
    email: str
    phone: str
    id_number: str | None = None


class SearchCustomersIn(BaseModel):
    query: str = Field(min_length=1, max_length=100)
    limit: int = Field(default=10, ge=1, le=50)


class SearchCustomersOut(BaseModel):
    customers: list[Customer]


class GetCustomerIn(BaseModel):
    customer_id: int


class CreateNoteIn(BaseModel):
    customer_id: int
    body: str = Field(min_length=1, max_length=2000)


class Note(BaseModel):
    id: int
    tenant_id: str
    customer_id: int
    body: str
    author: str


class Invoice(BaseModel):
    id: int
    tenant_id: str
    customer_id: int
    customer_name: str
    amount_zar: float
    status: str


class ListOpenInvoicesOut(BaseModel):
    invoices: list[Invoice]
    total_zar: float


# --- tools ------------------------------------------------------------------


@tool(
    "search_customers",
    input_model=SearchCustomersIn,
    output_model=SearchCustomersOut,
    scopes=("crm:read",),
    policy=ToolPolicy(max_payload_bytes=2048, allowed_args=frozenset({"query", "limit"})),
)
def search_customers(args: SearchCustomersIn, ctx: CallContext) -> SearchCustomersOut:
    """Search customers by name (case-insensitive substring) within your tenant."""
    tf = tenant_filter()
    rows = DB.execute(
        f"SELECT * FROM customers WHERE {tf.sql} AND lower(name) LIKE ? LIMIT ?",
        (*tf.params, f"%{args.query.lower()}%", args.limit),
    ).fetchall()
    return SearchCustomersOut(customers=[Customer(**dict(r)) for r in rows])


@tool(
    "get_customer",
    input_model=GetCustomerIn,
    output_model=Customer,
    scopes=("crm:read",),
)
def get_customer(args: GetCustomerIn, ctx: CallContext) -> Customer:
    """Fetch one customer by id. Ids from another tenant are simply not found."""
    tf = tenant_filter()
    row = DB.execute(
        f"SELECT * FROM customers WHERE {tf.sql} AND id = ?", (*tf.params, args.customer_id)
    ).fetchone()
    if row is None:
        raise LookupError(f"customer {args.customer_id} not found")
    return Customer(**dict(row))


def _deny_sql_looking_notes(arguments: dict[str, Any], principal: Any) -> str | None:
    body = str(arguments.get("body", ""))
    if "DELETE" in body.upper() or "DROP " in body.upper():
        return "note body looks like an injected SQL statement"
    return None


@tool(
    "create_note",
    input_model=CreateNoteIn,
    output_model=Note,
    scopes=("crm:read", "notes:write"),
    policy=ToolPolicy(max_payload_bytes=4096, deny_if=_deny_sql_looking_notes),
)
def create_note(args: CreateNoteIn, ctx: CallContext) -> Note:
    """Attach a note to a customer you own. Requires the notes:write scope."""
    tf = tenant_filter()
    owner = DB.execute(
        f"SELECT id FROM customers WHERE {tf.sql} AND id = ?", (*tf.params, args.customer_id)
    ).fetchone()
    if owner is None:
        raise LookupError(f"customer {args.customer_id} not found")
    cur = DB.execute(
        "INSERT INTO notes (tenant_id, customer_id, body, author) VALUES (?,?,?,?)",
        (tf.tenant_id, args.customer_id, args.body, ctx.principal.key_id),
    )
    DB.commit()
    return Note(
        id=cur.lastrowid, tenant_id=tf.tenant_id, customer_id=args.customer_id,
        body=args.body, author=ctx.principal.key_id,
    )


class EmptyIn(BaseModel):
    pass


@tool(
    "list_open_invoices",
    input_model=EmptyIn,
    output_model=ListOpenInvoicesOut,
    scopes=("crm:read",),
    rate_tier="free",
)
def list_open_invoices(args: EmptyIn, ctx: CallContext) -> ListOpenInvoicesOut:
    """Open invoices for your tenant with the outstanding total."""
    tf = tenant_filter("i.tenant_id")
    rows = DB.execute(
        f"""SELECT i.id, i.tenant_id, i.customer_id, c.name AS customer_name,
                   i.amount_zar, i.status
            FROM invoices i JOIN customers c ON c.id = i.customer_id
            WHERE {tf.sql} AND i.status = 'open' ORDER BY i.amount_zar DESC""",
        tf.params,
    ).fetchall()
    invoices = [Invoice(**dict(r)) for r in rows]
    return ListOpenInvoicesOut(invoices=invoices, total_zar=sum(i.amount_zar for i in invoices))


@resource("crm://schema", name="crm_schema", description="The CRM table definitions.")
def crm_schema(ctx: CallContext) -> str:
    return SCHEMA.strip()


# --- gateway assembly -------------------------------------------------------

DEMO_TIERS = {
    "free": Tier(capacity=3, refill_per_second=0.05),
    "standard": Tier(capacity=60, refill_per_second=1.0),
}

ACME_KEY = os.environ.get("CRM_ACME_KEY", "demo-acme-key")
GLOBEX_KEY = os.environ.get("CRM_GLOBEX_KEY", "demo-globex-key")


def build_gateway(*, audit_path: str | None = None) -> Gateway:
    auth = APIKeyAuth(salt=os.environ.get("MCP_GATEWAY_KEY_SALT", "demo-salt"))
    auth.add_key(
        ACME_KEY, tenant_id="acme", key_id="acme-agent",
        scopes=["tools:list", "tools:call", "resources:read", "crm:read", "notes:write"],
    )
    auth.add_key(
        GLOBEX_KEY, tenant_id="globex", key_id="globex-agent",
        scopes=["tools:list", "tools:call", "resources:read", "crm:read"],  # no notes:write
    )
    redis_url = os.environ.get("MCP_GATEWAY_REDIS_URL")
    limiter = (
        RedisRateLimiter(redis_url, DEMO_TIERS) if redis_url else MemoryRateLimiter(DEMO_TIERS)
    )
    audit = JSONLAuditLog(audit_path) if audit_path else MemoryAuditLog()
    return Gateway(
        tools=[search_customers, get_customer, create_note, list_open_invoices],
        resources=[crm_schema],
        auth=auth,
        limiter=limiter,
        audit=audit,
        name="crm-gateway",
        instructions="CRM tools scoped to your tenant. Emails and phone numbers are redacted.",
    )


gateway = build_gateway(audit_path=os.environ.get("MCP_GATEWAY_AUDIT_PATH"))
app = gateway.asgi()  # for `uvicorn examples.crm_server:app`


# --- the walkthrough --------------------------------------------------------


async def call(gw: Gateway, key: str, method: str, params: dict[str, Any], id_: int) -> Any:
    reply = await gw.dispatcher.dispatch(
        {"jsonrpc": "2.0", "id": id_, "method": method, "params": params},
        RequestContext(api_key=key, transport="demo"),
    )
    return reply


def show(title: str, reply: Any) -> None:
    print(f"\n== {title}")
    if "error" in reply:
        err = reply["error"]
        print(f"   DENIED  code={err['code']}  {err['message']}")
    elif reply["result"].get("isError"):
        print(f"   ERROR   isError=true  {reply['result']['content'][0]['text']}")
    else:
        print(f"   OK      {json.dumps(reply['result'].get('structuredContent'), indent=None)}")


async def demo() -> None:
    gw = build_gateway()
    print("crm-gateway demo - two tenants, four tools, one gateway")

    r = await call(gw, ACME_KEY, "tools/call", {"name": "search_customers",
                                                "arguments": {"query": "a"}}, 1)
    show("1. acme searches its customers - emails/phones/SA IDs are scrubbed", r)

    r = await call(gw, ACME_KEY, "tools/call", {"name": "get_customer",
                                                "arguments": {"customer_id": 4}}, 2)
    show("2. acme asks for customer 4, which belongs to globex", r)
    print("   (tool error, not a leak: the tenant filter never saw the row)")

    r = await call(gw, GLOBEX_KEY, "tools/call", {"name": "create_note",
                                                  "arguments": {"customer_id": 4,
                                                                "body": "Called re: invoice"}}, 3)
    show("3. globex tries create_note without the notes:write scope", r)

    r = await call(gw, ACME_KEY, "tools/call", {"name": "create_note",
                                                "arguments": {"customer_id": 1,
                                                              "body": "Called re: invoice"}}, 4)
    show("4. acme creates a note (has notes:write)", r)

    r = await call(gw, ACME_KEY, "tools/call", {"name": "create_note",
                                                "arguments": {"customer_id": 1,
                                                              "body": "DROP TABLE notes"}}, 5)
    show("5. acme's note trips the deny_if guardrail", r)

    print("\n== 6. list_open_invoices is on the 'free' tier (3 calls, slow refill)")
    for i in range(4):
        r = await call(gw, GLOBEX_KEY, "tools/call", {"name": "list_open_invoices",
                                                      "arguments": {}}, 10 + i)
        status = "OK" if "result" in r else f"DENIED code={r['error']['code']}"
        print(f"   call {i + 1}: {status}")

    print("\n== audit log (args hashed, never stored)")
    for rec in gw.audit.records:  # type: ignore[attr-defined]
        print(f"   {rec.tenant_id:<7} {rec.tool:<19} {rec.outcome:<7} "
              f"{rec.args_hash[:12]}...  {rec.latency_ms:>6.2f}ms  {rec.denial_reason or ''}")


def main(argv: list[str]) -> None:
    mode = argv[1] if len(argv) > 1 else "serve"
    if mode == "demo":
        asyncio.run(demo())
    elif mode == "serve":
        gateway.serve_stdio()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv)
