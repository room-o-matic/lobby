"""Long-lived API keys. An agent, agentd instance or roomsd server holds one and
exchanges it at /v1/token for short-lived, audience-bound access tokens."""

import hashlib
import re
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Literal

from lobbyd.ids import now_iso

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


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_key(conn: sqlite3.Connection, name: str, scope: Scope) -> str:
    if not NAME_RE.match(name):
        raise ValueError(f"invalid name {name!r}: use lowercase [a-z0-9_.-], max 64")
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {SCOPES}")
    other = conn.execute(
        "select scope from api_keys where name = ? and scope != ? limit 1", (name, scope)
    ).fetchone()
    if other:
        raise ValueError(f"{name!r} already has {other['scope']!r} keys")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    with conn:
        conn.execute(
            "insert into api_keys (key_hash, name, scope, created_at) values (?, ?, ?, ?)",
            (hash_key(key), name, scope, now_iso()),
        )
    return key


def revoke_keys(conn: sqlite3.Connection, name: str) -> int:
    with conn:
        cur = conn.execute(
            "update api_keys set revoked_at = ? where name = ? and revoked_at is null",
            (now_iso(), name),
        )
    return cur.rowcount


def holder_for_key(conn: sqlite3.Connection, key: str, domain: str) -> KeyHolder | None:
    row = conn.execute(
        "select name, scope from api_keys where key_hash = ? and revoked_at is null",
        (hash_key(key),),
    ).fetchone()
    if row is None:
        return None
    return KeyHolder(name=row["name"], scope=row["scope"], identity=f"{row['name']}@{domain}")
