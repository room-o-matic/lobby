"""Long-lived API keys. An agent, agentd instance or roomsd server holds one and
exchanges it at /v1/token for short-lived, audience-bound access tokens."""

import hashlib
import re
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Literal

from lobbyd.ids import new_id, now_iso

KEY_PREFIX = "lbk_"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

# agent:  a named agent (Boostie, Missy, …)
# agentd: an agentd instance; its name is its instance_id
# roomsd: a roomsd server; its name is its server_id
Scope = Literal["agent", "agentd", "roomsd"]
SCOPES: tuple[Scope, ...] = ("agent", "agentd", "roomsd")


@dataclass(frozen=True)
class KeyHolder:
    name: str
    scope: Scope
    identity: str  # name@domain
    tenant_id: str = "internal"
    key_id: str = ""


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_tenant(
    conn: sqlite3.Connection, tenant_id: str, *, name: str | None = None, can_host: bool = False
) -> None:
    if not NAME_RE.match(tenant_id):
        raise ValueError(f"invalid tenant id {tenant_id!r}")
    with conn:
        conn.execute(
            "insert into tenants (tenant_id, name, can_host, created_at) values (?, ?, ?, ?)",
            (tenant_id, name, int(can_host), now_iso()),
        )


def set_tenant_status(conn: sqlite3.Connection, tenant_id: str, status: str) -> bool:
    with conn:
        cur = conn.execute("update tenants set status = ? where tenant_id = ?", (status, tenant_id))
    return cur.rowcount == 1


def create_key(
    conn: sqlite3.Connection,
    name: str,
    scope: Scope,
    *,
    tenant_id: str = "internal",
    label: str | None = None,
) -> str:
    """Issue a key for `name` in `tenant_id`. The first key for a name reserves it for that
    tenant (docs#11); service scopes need a tenant that may host services."""
    if not NAME_RE.match(name):
        raise ValueError(f"invalid name {name!r}: use lowercase [a-z0-9_.-], max 64")
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {SCOPES}")
    tenant = conn.execute("select * from tenants where tenant_id = ?", (tenant_id,)).fetchone()
    if tenant is None:
        raise ValueError(f"no tenant {tenant_id!r}")
    if scope in ("roomsd", "agentd") and not tenant["can_host"]:
        raise ValueError(f"tenant {tenant_id!r} may not hold service ({scope}) keys")
    other = conn.execute(
        "select scope, tenant_id from api_keys where name = ? limit 1", (name,)
    ).fetchone()
    if other and other["scope"] != scope:
        raise ValueError(f"{name!r} already has {other['scope']!r} keys")
    if other and other["tenant_id"] != tenant_id:
        raise ValueError(f"{name!r} is reserved by tenant {other['tenant_id']!r}")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    with conn:
        conn.execute(
            "insert into api_keys (key_hash, key_id, name, scope, tenant_id, label, created_at)"
            " values (?, ?, ?, ?, ?, ?, ?)",
            (hash_key(key), new_id("key"), name, scope, tenant_id, label, now_iso()),
        )
    return key


def revoke_keys(conn: sqlite3.Connection, name: str) -> int:
    """Revoke every key for a name. Tokens already issued stay valid until they expire."""
    with conn:
        cur = conn.execute(
            "update api_keys set revoked_at = ? where name = ? and revoked_at is null",
            (now_iso(), name),
        )
    return cur.rowcount


def revoke_key_id(conn: sqlite3.Connection, key_id: str) -> bool:
    """Revoke one credential (e.g. one deployment of an identity), leaving the others."""
    with conn:
        cur = conn.execute(
            "update api_keys set revoked_at = ? where key_id = ? and revoked_at is null",
            (now_iso(), key_id),
        )
    return cur.rowcount == 1


def holder_for_key(conn: sqlite3.Connection, key: str, domain: str) -> KeyHolder | None:
    row = conn.execute(
        "select k.name, k.scope, k.tenant_id, k.key_id from api_keys k"
        " join tenants t on t.tenant_id = k.tenant_id"
        " where k.key_hash = ? and k.revoked_at is null and t.status = 'active'",
        (hash_key(key),),
    ).fetchone()
    if row is None:
        return None
    return KeyHolder(
        name=row["name"],
        scope=row["scope"],
        identity=f"{row['name']}@{domain}",
        tenant_id=row["tenant_id"],
        key_id=row["key_id"],
    )


def tenant_of(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute("select tenant_id from api_keys where name = ? limit 1", (name,)).fetchone()
    return row["tenant_id"] if row else None
