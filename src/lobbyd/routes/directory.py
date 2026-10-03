"""The directory: roomsd servers, agentd instances, and listed rooms.

Servers and instances are leases: each re-PUTs its own entry (a heartbeat) before
`expires_at`, and lapsed entries are invisible. Listed rooms belong to a server and
are only shown while that server's lease is live.
"""

import json
import sqlite3
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Response, status

from lobbyd import db
from lobbyd.deps import (
    Caller,
    Conn,
    SettingsDep,
    lease_registered_at,
    lease_ttl,
    require_scope,
    require_self,
)
from lobbyd.ids import iso_in, now_iso
from lobbyd.models import (
    AgentdInstance,
    AgentdRegistration,
    ListedRoom,
    RoomListing,
    RoomsdRegistration,
    RoomsdServer,
)

router = APIRouter(prefix="/v1", tags=["directory"])

EntryId = Annotated[str, Path(max_length=64)]


def _json(value) -> str | None:
    return json.dumps(value) if value is not None else None


def _loads(value: str | None):
    return json.loads(value) if value else None


# ----- roomsd servers ---------------------------------------------------------------


def server_from_row(row: sqlite3.Row) -> RoomsdServer:
    return RoomsdServer(
        server_id=row["server_id"],
        base_url=row["base_url"],
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
    ttl = lease_ttl(settings, req.ttl_seconds)
    now = now_iso()
    registered_at, is_new = lease_registered_at(conn, "roomsd_servers", "server_id", server_id, now)
    with conn:
        conn.execute(
            "insert or replace into roomsd_servers (server_id, base_url, tags_json,"
            " metadata_json, registered_at, last_heartbeat_at, expires_at)"
            " values (?, ?, ?, ?, ?, ?, ?)",
            (
                server_id,
                req.base_url.rstrip("/"),
                json.dumps(req.tags),
                _json(req.metadata),
                registered_at,
                now,
                iso_in(ttl),
            ),
        )
        if is_new:
            db.audit(conn, caller.identity, "server.register", base_url=req.base_url)
    row = conn.execute("select * from roomsd_servers where server_id = ?", (server_id,)).fetchone()
    return server_from_row(row)


@router.delete(
    "/servers/roomsd/{server_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["servers"]
)
def deregister_server(server_id: EntryId, conn: Conn, caller: Caller) -> Response:
    require_self(caller, "roomsd", server_id)
    with conn:
        conn.execute("delete from roomsd_servers where server_id = ?", (server_id,))
        db.audit(conn, caller.identity, "server.deregister")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/servers/roomsd", tags=["servers"])
def list_servers(conn: Conn, caller: Caller, tag: str | None = None) -> list[RoomsdServer]:
    require_scope(caller, "agent", "roomsd")
    sql, params = "select * from roomsd_servers where expires_at > ?", [now_iso()]
    if tag:
        sql += " and exists (select 1 from json_each(tags_json) where value = ?)"
        params.append(tag)
    rows = conn.execute(sql + " order by server_id", params).fetchall()
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
                req.base_url.rstrip("/"),
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
            db.audit(conn, caller.identity, "registry.register", base_url=req.base_url)
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
) -> list[AgentdInstance]:
    """Live instances, most spare capacity first."""
    require_scope(caller, "agent")
    sql = "select * from agentd_instances where expires_at > ?"
    params: list = [now_iso()]
    if worker_type:
        sql += " and exists (select 1 from json_each(worker_types_json) where value = ?)"
        params.append(worker_type)
    if profile:
        sql += " and exists (select 1 from json_each(profiles_json) where value = ?)"
        params.append(profile)
    if has_capacity:
        sql += " and active_sessions < max_sessions"
    sql += " order by (max_sessions - active_sessions) desc, last_heartbeat_at desc"
    return [instance_from_row(r) for r in conn.execute(sql, params).fetchall()]


@router.get("/registry/agentd/{instance_id}", tags=["registry"])
def get_instance(instance_id: EntryId, conn: Conn, caller: Caller) -> AgentdInstance:
    if caller.scope != "agentd" or caller.name != instance_id:
        require_scope(caller, "agent")
    row = conn.execute(
        "select * from agentd_instances where instance_id = ? and expires_at > ?",
        (instance_id, now_iso()),
    ).fetchone()
    if row is None:
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


def require_own_room_url(conn: sqlite3.Connection, server_id: str, room_url: str) -> None:
    """A server may only list rooms under its own registered base_url."""
    server = conn.execute(
        "select base_url from roomsd_servers where server_id = ? and expires_at > ?",
        (server_id, now_iso()),
    ).fetchone()
    if server is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "register this server before listing rooms")
    if not room_url.startswith(server["base_url"] + "/v1/rooms/"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"room_url must be under {server['base_url']}/v1/rooms/"
        )


@router.put("/rooms", tags=["rooms"])
def list_room(req: RoomListing, conn: Conn, caller: Caller) -> ListedRoom:
    require_scope(caller, "roomsd")
    require_own_room_url(conn, caller.name, req.room_url)
    with conn:
        conn.execute(
            "insert or replace into listed_rooms"
            " (room_url, server_id, name, purpose, tags_json, updated_at)"
            " values (?, ?, ?, ?, ?, ?)",
            (req.room_url, caller.name, req.name, req.purpose, json.dumps(req.tags), now_iso()),
        )
        db.audit(conn, caller.identity, "room.list", room_url=req.room_url)
    row = conn.execute("select * from listed_rooms where room_url = ?", (req.room_url,)).fetchone()
    return room_from_row(row)


@router.delete("/rooms", status_code=status.HTTP_204_NO_CONTENT, tags=["rooms"])
def unlist_room(room_url: str, conn: Conn, caller: Caller) -> Response:
    require_scope(caller, "roomsd")
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
        " where s.expires_at > ?"
    )
    params: list = [now_iso()]
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
