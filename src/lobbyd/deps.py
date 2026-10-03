import sqlite3
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lobbyd import apikeys, db
from lobbyd.apikeys import KeyHolder, Scope
from lobbyd.config import Settings

_bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    conn = db.connect(request.app.state.settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


SettingsDep = Annotated[Settings, Depends(get_settings)]
Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


def current_holder(
    conn: Conn,
    settings: SettingsDep,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> KeyHolder:
    """lobbyd's own endpoints authenticate with the API key itself, not access tokens."""
    holder = apikeys.holder_for_key(conn, creds.credentials, settings.domain) if creds else None
    if holder is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing, invalid, or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return holder


Caller = Annotated[KeyHolder, Depends(current_holder)]


def require_scope(caller: KeyHolder, *scopes: Scope) -> None:
    if caller.scope not in scopes:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"{caller.scope!r} keys cannot use this endpoint"
        )


def require_self(caller: KeyHolder, scope: Scope, name: str) -> None:
    """Directory entries are owned by the key whose name they carry."""
    require_scope(caller, scope)
    if caller.name != name:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"key belongs to {caller.name!r}; cannot manage {name!r}"
        )


def lease_ttl(settings: Settings, requested: int | None) -> int:
    ttl = requested or settings.default_lease_ttl_seconds
    if ttl > settings.max_lease_ttl_seconds:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"ttl_seconds may not exceed {settings.max_lease_ttl_seconds}",
        )
    return ttl


def lease_registered_at(
    conn: sqlite3.Connection, table: str, key_col: str, key: str, now: str
) -> tuple[str, bool]:
    """Keep registered_at across heartbeats; reset it if the previous lease had lapsed."""
    prev = conn.execute(
        f"select registered_at, expires_at from {table} where {key_col} = ?", (key,)
    ).fetchone()
    if prev is None or prev["expires_at"] <= now:
        return now, True
    return prev["registered_at"], False
