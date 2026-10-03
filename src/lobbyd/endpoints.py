"""Operator-approved service endpoints (room-o-matic/docs#5).

A roomsd or agentd key may only register at an endpoint the operator approved for that
key's name. Each canonical URL belongs to exactly one name (a name may hold several URLs
as explicit aliases). Approval is an operator action (CLI); lobbyd never calls out to a
service to verify it, which keeps the one-way dependency rule.
"""

import json
import sqlite3

from lobbyd import db
from lobbyd.ids import now_iso
from lobbyd.urls import canonical_url

# Hard ceilings for claims a service makes about itself, whatever was approved.
MAX_SESSIONS_CEILING = 10_000
DEFAULT_MAX_SESSIONS = 64


def approve(
    conn: sqlite3.Connection,
    name: str,
    url: str,
    *,
    max_sessions: int | None = None,
    worker_types: list[str] | None = None,
) -> dict:
    """Approve `url` for the roomsd/agentd key `name`. Raises ValueError on conflicts."""
    canonical = canonical_url(url)
    key = conn.execute(
        "select scope from api_keys where name = ? and revoked_at is null limit 1", (name,)
    ).fetchone()
    if key is None or key["scope"] not in ("roomsd", "agentd"):
        raise ValueError(f"{name!r} has no live roomsd/agentd key; create the key first")
    cap = max_sessions if max_sessions is not None else DEFAULT_MAX_SESSIONS
    if not 0 <= cap <= MAX_SESSIONS_CEILING:
        raise ValueError(f"max_sessions must be between 0 and {MAX_SESSIONS_CEILING}")
    with conn:
        conn.execute("begin immediate")
        owner = conn.execute("select name from endpoints where url = ?", (canonical,)).fetchone()
        if owner and owner["name"] != name:
            raise ValueError(f"{canonical} is already approved for {owner['name']!r}")
        conn.execute(
            "insert or replace into endpoints"
            " (url, name, scope, max_sessions, worker_types_json, approved_at)"
            " values (?, ?, ?, ?, ?, ?)",
            (
                canonical,
                name,
                key["scope"],
                cap,
                json.dumps(worker_types) if worker_types else None,
                now_iso(),
            ),
        )
        db.audit(conn, "operator", "endpoint.approve", name=name, url=canonical)
    return {"url": canonical, "name": name, "scope": key["scope"], "max_sessions": cap}


def revoke(conn: sqlite3.Connection, url: str) -> int:
    """Withdraw approval and drop any live registration using the endpoint."""
    canonical = canonical_url(url)
    with conn:
        n = conn.execute("delete from endpoints where url = ?", (canonical,)).rowcount
        conn.execute("delete from roomsd_servers where base_url = ?", (canonical,))
        conn.execute("delete from agentd_instances where base_url = ?", (canonical,))
        if n:
            db.audit(conn, "operator", "endpoint.revoke", url=canonical)
    return n


def lookup(conn: sqlite3.Connection, url: str) -> sqlite3.Row | None:
    """The approval for a canonical URL, if any."""
    return conn.execute("select * from endpoints where url = ?", (url,)).fetchone()
