"""The directory: roomsd servers, agentd instances, and listed rooms.

Servers and instances are leases: each re-PUTs its own entry (a heartbeat) before
`expires_at`, and lapsed entries are invisible. Listed rooms belong to a server and
are only shown while that server's lease is live.
"""

import json
import re
import sqlite3
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Response, status

from lobbyd import db, endpoints
from lobbyd.deps import (
    Caller,
    Conn,
    SettingsDep,
    lease_registered_at,
    lease_ttl,
    require_scope,
    require_self,
)
from lobbyd.ids import iso_in, new_id, now_iso
from lobbyd.models import (
    AgentdInstance,
    AgentdRegistration,
    ListedRoom,
    RoomListing,
    RoomsdRegistration,
    RoomsdServer,
)
from lobbyd.urls import canonical_url

router = APIRouter(prefix="/v1", tags=["directory"])

EntryId = Annotated[str, Path(max_length=64)]
ROOM_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def canonical_or_422(url: str) -> str:
    try:
        return canonical_url(url)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"bad URL {url!r}: {e}") from e


def require_endpoint(conn: sqlite3.Connection, caller, base_url: str) -> sqlite3.Row:
    """Registration must use an endpoint the operator approved for this key (docs#5):
    owning a name is not owning an endpoint."""
    url = canonical_or_422(base_url)
    approval = endpoints.lookup(conn, url)
    if approval is None or approval["name"] != caller.name or approval["scope"] != caller.scope:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"{url} is not an approved endpoint for {caller.name!r}; an operator must run"
            f" `lobbyd endpoint approve {caller.name} <url>`",
        )
    return approval


def _json(value) -> str | None:
    return json.dumps(value) if value is not None else None


def _loads(value: str | None):
    return json.loads(value) if value else None


# ----- roomsd servers ---------------------------------------------------------------


def server_from_row(row: sqlite3.Row, listed_rooms: int = 0) -> RoomsdServer:
    return RoomsdServer(
        server_id=row["server_id"],
        base_url=row["base_url"],
        registration_id=row["registration_id"],
        listed_rooms=listed_rooms,
        tags=json.loads(row["tags_json"]),
        metadata=_loads(row["metadata_json"]),
        registered_at=row["registered_at"],
        last_heartbeat_at=row["last_heartbeat_at"],
        expires_at=row["expires_at"],
    )


@router.put("/servers/roomsd/{server_id}", tags=["servers"])
def register_server(
    server_id: EntryId,
    req: RoomsdRegistration,
    conn: Conn,
    caller: Caller,
    settings: SettingsDep,
) -> RoomsdServer:
    require_self(caller, "roomsd", server_id)
    base_url = require_endpoint(conn, caller, req.base_url)["url"]
    ttl = lease_ttl(settings, req.ttl_seconds)
    now = now_iso()
    registered_at, is_new = lease_registered_at(conn, "roomsd_servers", "server_id", server_id, now)
    with conn:
        conn.execute("begin immediate")
        prev = conn.execute(
            "select base_url, registration_id from roomsd_servers where server_id = ?",
            (server_id,),
        ).fetchone()
        if prev is not None and prev["base_url"] == base_url:
            registration_id = prev["registration_id"]  # heartbeat or lapse recovery
        else:
            # New registration or endpoint migration: listings published under any earlier
            # registration of this server are retired, not carried over (docs#19).
            registration_id = new_id("reg")
            conn.execute("delete from listed_rooms where server_id = ?", (server_id,))
            if prev is not None:
                db.audit(
                    conn, caller.identity, "server.migrate", old=prev["base_url"], new=base_url
                )
        conn.execute(
            "insert or replace into roomsd_servers (server_id, base_url, registration_id,"
            " tags_json, metadata_json, registered_at, last_heartbeat_at, expires_at)"
            " values (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                server_id,
                base_url,
                registration_id,
                json.dumps(req.tags),
                _json(req.metadata),
                registered_at,
                now,
                iso_in(ttl),
            ),
        )
        if is_new:
            db.audit(conn, caller.identity, "server.register", base_url=base_url)
        row = conn.execute(
            "select * from roomsd_servers where server_id = ?", (server_id,)
        ).fetchone()
        listed = conn.execute(
            "select count(*) from listed_rooms where server_id = ? and registration_id = ?",
            (server_id, registration_id),
        ).fetchone()[0]
    return server_from_row(row, listed)


@router.delete(
    "/servers/roomsd/{server_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["servers"]
)
def deregister_server(server_id: EntryId, conn: Conn, caller: Caller) -> Response:
    require_self(caller, "roomsd", server_id)
    with conn:
        # Explicit deletion retires the registration and its listings: re-registering the
        # same id later starts a new registration and can't resurrect them (docs#19).
        conn.execute("delete from roomsd_servers where server_id = ?", (server_id,))
        conn.execute("delete from listed_rooms where server_id = ?", (server_id,))
        db.audit(conn, caller.identity, "server.deregister")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/servers/roomsd", tags=["servers"])
def list_servers(
    conn: Conn,
    caller: Caller,
    tag: str | None = None,
    after: str | None = Query(default=None, description="server_id to continue after"),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[RoomsdServer]:
    """Live servers visible to the caller's tenant (its own and granted endpoints)."""
    require_scope(caller, "agent", "roomsd")
    sql = (
        f"select * from roomsd_servers where expires_at > ? and {endpoints.visible_sql('base_url')}"
    )
    params = [now_iso(), caller.tenant_id, caller.tenant_id]
    if tag:
        sql += " and exists (select 1 from json_each(tags_json) where value = ?)"
        params.append(tag)
    if after:
        sql += " and server_id > ?"
        params.append(after)
    rows = conn.execute(sql + " order by server_id limit ?", [*params, limit]).fetchall()
    return [server_from_row(r) for r in rows]


# ----- agentd registry --------------------------------------------------------------


def instance_from_row(row: sqlite3.Row) -> AgentdInstance:
    return AgentdInstance(
        instance_id=row["instance_id"],
        base_url=row["base_url"],
        worker_types=json.loads(row["worker_types_json"]),
        profiles=json.loads(row["profiles_json"]),
        max_sessions=row["max_sessions"],
        active_sessions=row["active_sessions"],
        available_sessions=max(0, row["max_sessions"] - row["active_sessions"]),
        metadata=_loads(row["metadata_json"]),
        registered_at=row["registered_at"],
        last_heartbeat_at=row["last_heartbeat_at"],
        expires_at=row["expires_at"],
    )


@router.put("/registry/agentd/{instance_id}", tags=["registry"])
def register_instance(
    instance_id: EntryId,
    req: AgentdRegistration,
    conn: Conn,
    caller: Caller,
    settings: SettingsDep,
) -> AgentdInstance:
    """Register or heartbeat. The same call does both; send it every ttl/3 or so."""
    require_self(caller, "agentd", instance_id)
    approval = require_endpoint(conn, caller, req.base_url)
    base_url = approval["url"]
    # Capacity and worker types are claims; bound them by what was approved (docs#5).
    if req.max_sessions > approval["max_sessions"]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"max_sessions {req.max_sessions} exceeds the approved {approval['max_sessions']}",
        )
    if req.active_sessions > req.max_sessions:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "active_sessions exceeds max_sessions"
        )
    allowed = json.loads(approval["worker_types_json"]) if approval["worker_types_json"] else None
    if allowed is not None and not set(req.worker_types) <= set(allowed):
        extra = sorted(set(req.worker_types) - set(allowed))
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"worker types not approved: {extra}"
        )
    ttl = lease_ttl(settings, req.ttl_seconds)
    now = now_iso()
    registered_at, is_new = lease_registered_at(
        conn, "agentd_instances", "instance_id", instance_id, now
    )
    with conn:
        conn.execute(
            "insert or replace into agentd_instances (instance_id, base_url, worker_types_json,"
            " profiles_json, max_sessions, active_sessions, metadata_json, registered_at,"
            " last_heartbeat_at, expires_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                instance_id,
                base_url,
                json.dumps(req.worker_types),
                json.dumps(req.profiles),
                req.max_sessions,
                req.active_sessions,
                _json(req.metadata),
                registered_at,
                now,
                iso_in(ttl),
            ),
        )
        # Heartbeats are frequent; only audit (re)registrations.
        if is_new:
            db.audit(conn, caller.identity, "registry.register", base_url=base_url)
    row = conn.execute(
        "select * from agentd_instances where instance_id = ?", (instance_id,)
    ).fetchone()
    return instance_from_row(row)


@router.delete(
    "/registry/agentd/{instance_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["registry"]
)
def deregister_instance(instance_id: EntryId, conn: Conn, caller: Caller) -> Response:
    require_self(caller, "agentd", instance_id)
    with conn:
        conn.execute("delete from agentd_instances where instance_id = ?", (instance_id,))
        db.audit(conn, caller.identity, "registry.deregister")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/registry/agentd", tags=["registry"])
def list_instances(
    conn: Conn,
    caller: Caller,
    worker_type: str | None = None,
    profile: str | None = None,
    has_capacity: Annotated[bool, Query(description="only instances with a free slot")] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AgentdInstance]:
    """Live instances, most spare capacity first."""
    require_scope(caller, "agent")
    sql = (
        "select * from agentd_instances where expires_at > ?"
        f" and {endpoints.visible_sql('base_url')}"
    )
    params: list = [now_iso(), caller.tenant_id, caller.tenant_id]
    if worker_type:
        sql += " and exists (select 1 from json_each(worker_types_json) where value = ?)"
        params.append(worker_type)
    if profile:
        sql += " and exists (select 1 from json_each(profiles_json) where value = ?)"
        params.append(profile)
    if has_capacity:
        sql += " and active_sessions < max_sessions"
    sql += " order by (max_sessions - active_sessions) desc, last_heartbeat_at desc limit ?"
    return [instance_from_row(r) for r in conn.execute(sql, [*params, limit]).fetchall()]


@router.get("/registry/agentd/{instance_id}", tags=["registry"])
def get_instance(instance_id: EntryId, conn: Conn, caller: Caller) -> AgentdInstance:
    if caller.scope != "agentd" or caller.name != instance_id:
        require_scope(caller, "agent")
    row = conn.execute(
        "select * from agentd_instances where instance_id = ? and expires_at > ?",
        (instance_id, now_iso()),
    ).fetchone()
    if row is None or not endpoints.visible(conn, caller.tenant_id, row["base_url"]):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "instance not registered or expired")
    return instance_from_row(row)


# ----- listed rooms -----------------------------------------------------------------


def room_from_row(row: sqlite3.Row) -> ListedRoom:
    return ListedRoom(
        room_url=row["room_url"],
        server_id=row["server_id"],
        name=row["name"],
        purpose=row["purpose"],
        tags=json.loads(row["tags_json"]),
        updated_at=row["updated_at"],
    )


def require_own_room_url(conn: sqlite3.Connection, server_id: str, room_url: str) -> str:
    """A server may only list rooms under its own registered base_url. Returns the
    canonical room URL."""
    room_url = canonical_or_422(room_url)
    server = conn.execute(
        "select base_url from roomsd_servers where server_id = ? and expires_at > ?",
        (server_id, now_iso()),
    ).fetchone()
    if server is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "register this server before listing rooms")
    prefix = server["base_url"] + "/v1/rooms/"
    if not room_url.startswith(prefix) or not ROOM_ID_RE.match(room_url[len(prefix) :]):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"room_url must be {prefix}<room_id>")
    return room_url


@router.put("/rooms", tags=["rooms"])
def list_room(req: RoomListing, conn: Conn, caller: Caller, settings: SettingsDep) -> ListedRoom:
    require_scope(caller, "roomsd")
    room_url = require_own_room_url(conn, caller.name, req.room_url)
    listed = conn.execute(
        "select count(*) from listed_rooms where server_id = ? and room_url != ?",
        (caller.name, room_url),
    ).fetchone()[0]
    if listed >= settings.max_listed_rooms_per_server:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"listing budget reached ({settings.max_listed_rooms_per_server} rooms per server)",
        )
    with conn:
        # The WHERE makes the ownership check and the write one atomic statement: a
        # listing owned by another server is never overwritten (docs#5).
        cur = conn.execute(
            "insert into listed_rooms"
            " (room_url, server_id, registration_id, name, purpose, tags_json, updated_at)"
            " values (?, ?, (select registration_id from roomsd_servers where server_id = ?),"
            " ?, ?, ?, ?)"
            " on conflict (room_url) do update set name = excluded.name,"
            " purpose = excluded.purpose, tags_json = excluded.tags_json,"
            " updated_at = excluded.updated_at"
            " where listed_rooms.server_id = excluded.server_id",
            (
                room_url,
                caller.name,
                caller.name,
                req.name,
                req.purpose,
                json.dumps(req.tags),
                now_iso(),
            ),
        )
        if cur.rowcount == 0:
            raise HTTPException(status.HTTP_409_CONFLICT, "room is listed by another server")
        db.audit(conn, caller.identity, "room.list", room_url=room_url)
    row = conn.execute("select * from listed_rooms where room_url = ?", (room_url,)).fetchone()
    return room_from_row(row)


@router.delete("/rooms", status_code=status.HTTP_204_NO_CONTENT, tags=["rooms"])
def unlist_room(room_url: str, conn: Conn, caller: Caller) -> Response:
    require_scope(caller, "roomsd")
    room_url = canonical_or_422(room_url)
    with conn:
        cur = conn.execute(
            "delete from listed_rooms where room_url = ? and server_id = ?",
            (room_url, caller.name),
        )
        if cur.rowcount:
            db.audit(conn, caller.identity, "room.unlist", room_url=room_url)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/rooms", tags=["rooms"])
def search_rooms(
    conn: Conn,
    caller: Caller,
    q: Annotated[str | None, Query(max_length=200, description="matches name or purpose")] = None,
    tag: str | None = None,
    server_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[ListedRoom]:
    """Listed rooms on live servers."""
    require_scope(caller, "agent", "roomsd")
    sql = (
        "select r.* from listed_rooms r join roomsd_servers s on s.server_id = r.server_id"
        # docs#19: only listings of the server's current registration, under its current
        # prefix, are ever shown.
        " and s.registration_id = r.registration_id"
        " and substr(r.room_url, 1, length(s.base_url) + 10) = s.base_url || '/v1/rooms/'"
        f" where s.expires_at > ? and {endpoints.visible_sql('s.base_url')}"
    )
    params: list = [now_iso(), caller.tenant_id, caller.tenant_id]
    if q:
        sql += " and (r.name like ? escape '\\' or r.purpose like ? escape '\\')"
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params += [pattern, pattern]
    if tag:
        sql += " and exists (select 1 from json_each(r.tags_json) where value = ?)"
        params.append(tag)
    if server_id:
        sql += " and r.server_id = ?"
        params.append(server_id)
    rows = conn.execute(sql + " order by r.updated_at desc limit ?", [*params, limit]).fetchall()
    return [room_from_row(r) for r in rows]
