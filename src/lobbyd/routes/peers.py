"""Peers and room-work offers (room-o-matic/docs#7).

Independent named agents (Boostie, Missy, a running Claude/Codex session) register a
*session instance* here and poll an inbox for offers of room work. This is deliberately
separate from agentd's registry: summon spawns a new worker; an offer asks an existing peer,
which may decline. lobbyd stores state and calls nobody, so peers behind NAT or inside a
local CLI work by polling outbound.

Offer lifecycle (every transition is a conditional update inside one transaction):

    offered -> accepted | declined | expired | cancelled
    accepted -> joined -> working -> handed_off | completed     (by the accepting instance)
    offered/accepted/joined/working -> cancelled                (by the requester)

Repeating the transition that already happened is idempotent and returns changed=false,
so a peer that reconnects and re-reports "working" knows not to start the work again.
An offer grants nothing: the peer joins the room with its own identity, subject to
roomsd's admission rules, and sees no room history through lobbyd.
"""

import json
import re
import sqlite3
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, Response, status

from lobbyd import db
from lobbyd.apikeys import KeyHolder
from lobbyd.deps import (
    Caller,
    Conn,
    SettingsDep,
    lease_registered_at,
    lease_ttl,
    require_scope,
)
from lobbyd.ids import iso_in, new_id, now_iso
from lobbyd.models import (
    Offer,
    OfferCreate,
    OfferProgress,
    OfferTransition,
    Peer,
    PeerRegistration,
    TransitionResult,
)
from lobbyd.urls import canonical_url

router = APIRouter(prefix="/v1", tags=["peers"])

InstanceId = Annotated[str, Path(pattern=r"^[A-Za-z0-9_.:-]{1,80}$")]
ROOM_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
ACTIVE_STATES = ("accepted", "joined", "working")
PROGRESS_ORDER = {"accepted": 0, "joined": 1, "working": 2, "handed_off": 3, "completed": 3}


def _loads(value):
    return json.loads(value) if value else None


def offer_from_row(row: sqlite3.Row) -> Offer:
    return Offer(
        offer_id=row["offer_id"],
        requester=row["requester"],
        target=row["target"],
        room_url=row["room_url"],
        task=row["task"],
        issue=row["issue"],
        role=row["role"],
        scope=_loads(row["scope_json"]),
        budget=_loads(row["budget_json"]),
        deadline=row["deadline"],
        state=row["state"],
        assigned_instance=row["assigned_instance"],
        decline_reason=row["decline_reason"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _active_count(conn: sqlite3.Connection, instance_id: str) -> int:
    placeholders = ",".join("?" * len(ACTIVE_STATES))
    return conn.execute(
        f"select count(*) from offers where assigned_instance = ? and state in ({placeholders})",
        (instance_id, *ACTIVE_STATES),
    ).fetchone()[0]


def peer_from_row(conn: sqlite3.Connection, row: sqlite3.Row) -> Peer:
    return Peer(
        instance_id=row["instance_id"],
        principal=row["principal"],
        owner=row["owner"],
        capabilities=json.loads(row["capabilities_json"]),
        availability=row["availability"],
        max_assignments=row["max_assignments"],
        active_assignments=_active_count(conn, row["instance_id"]),
        registered_at=row["registered_at"],
        last_heartbeat_at=row["last_heartbeat_at"],
        expires_at=row["expires_at"],
    )


def _expire_offers(conn: sqlite3.Connection) -> None:
    """Offers past their respond-by deadline expire lazily, on any offer operation."""
    now = now_iso()
    with conn:
        conn.execute(
            "update offers set state = 'expired', updated_at = ?"
            " where state = 'offered' and deadline is not null and deadline <= ?",
            (now, now),
        )


def _own_live_instance(conn: sqlite3.Connection, caller: KeyHolder, instance_id: str):
    require_scope(caller, "agent")
    row = conn.execute(
        "select * from peers where instance_id = ? and expires_at > ?", (instance_id, now_iso())
    ).fetchone()
    if row is None or row["principal"] != caller.identity:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "no live peer instance with that id for this key"
        )
    return row


def _offer_or_404(conn: sqlite3.Connection, offer_id: str, caller: KeyHolder) -> sqlite3.Row:
    row = conn.execute("select * from offers where offer_id = ?", (offer_id,)).fetchone()
    if row is None or caller.identity not in (row["requester"], row["target"]):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "offer not found")
    return row


def _set_state(conn: sqlite3.Connection, offer_id: str, expect: str, new: str, **cols) -> bool:
    sets = ", ".join(f"{k} = ?" for k in cols)
    sql = f"update offers set state = ?, updated_at = ?{', ' + sets if sets else ''}"
    cur = conn.execute(
        sql + " where offer_id = ? and state = ?",
        (new, now_iso(), *cols.values(), offer_id, expect),
    )
    return cur.rowcount == 1


def _result(conn: sqlite3.Connection, offer_id: str, changed: bool) -> TransitionResult:
    row = conn.execute("select * from offers where offer_id = ?", (offer_id,)).fetchone()
    return TransitionResult(offer=offer_from_row(row), changed=changed)


def _conflict(row: sqlite3.Row, what: str) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, f"cannot {what}: offer is {row['state']}")


# ----- peers ---------------------------------------------------------------------------


@router.put("/peers/{instance_id}")
def register_peer(
    instance_id: InstanceId,
    req: PeerRegistration,
    conn: Conn,
    caller: Caller,
    settings: SettingsDep,
) -> Peer:
    """Register or heartbeat one running session of the calling agent. Use a fresh
    instance_id per session; heartbeats are presence, never consent to work."""
    require_scope(caller, "agent")
    existing = conn.execute(
        "select principal from peers where instance_id = ?", (instance_id,)
    ).fetchone()
    if existing and existing["principal"] != caller.identity:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "instance id belongs to another agent")
    ttl = lease_ttl(settings, req.ttl_seconds)
    now = now_iso()
    registered_at, is_new = lease_registered_at(conn, "peers", "instance_id", instance_id, now)
    with conn:
        conn.execute(
            "insert or replace into peers (instance_id, principal, owner, capabilities_json,"
            " availability, max_assignments, registered_at, last_heartbeat_at, expires_at)"
            " values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                instance_id,
                caller.identity,
                req.owner,
                json.dumps(req.capabilities),
                req.availability,
                req.max_assignments,
                registered_at,
                now,
                iso_in(ttl),
            ),
        )
        if is_new:
            db.audit(conn, caller.identity, "peer.register", instance_id=instance_id)
    row = conn.execute("select * from peers where instance_id = ?", (instance_id,)).fetchone()
    return peer_from_row(conn, row)


@router.delete("/peers/{instance_id}", status_code=status.HTTP_204_NO_CONTENT)
def deregister_peer(instance_id: InstanceId, conn: Conn, caller: Caller) -> Response:
    require_scope(caller, "agent")
    with conn:
        conn.execute(
            "delete from peers where instance_id = ? and principal = ?",
            (instance_id, caller.identity),
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/peers")
def list_peers(
    conn: Conn,
    caller: Caller,
    capability: str | None = None,
    principal: str | None = None,
    available: Annotated[bool, Query(description="only instances able to accept now")] = False,
) -> list[Peer]:
    """Live peer instances (lapsed leases are offline and not shown)."""
    require_scope(caller, "agent")
    sql, params = "select * from peers where expires_at > ?", [now_iso()]
    if capability:
        sql += " and exists (select 1 from json_each(capabilities_json) where value = ?)"
        params.append(capability)
    if principal:
        sql += " and principal = ?"
        params.append(principal)
    peers = [peer_from_row(conn, r) for r in conn.execute(sql + " order by principal", params)]
    if available:
        peers = [
            p
            for p in peers
            if p.availability == "available" and p.active_assignments < p.max_assignments
        ]
    return peers


@router.get("/peers/{instance_id}/inbox")
def inbox(instance_id: InstanceId, conn: Conn, caller: Caller) -> list[Offer]:
    """Offers this session should see: open offers to its principal (unless draining) and
    offers it has already accepted that aren't finished, so a reconnect loses nothing."""
    peer = _own_live_instance(conn, caller, instance_id)
    _expire_offers(conn)
    placeholders = ",".join("?" * len(ACTIVE_STATES))
    assigned = conn.execute(
        f"select * from offers where assigned_instance = ? and state in ({placeholders})"
        " order by created_at",
        (instance_id, *ACTIVE_STATES),
    ).fetchall()
    open_offers = []
    if peer["availability"] != "draining":
        open_offers = conn.execute(
            "select * from offers where target = ? and state = 'offered' order by created_at",
            (caller.identity,),
        ).fetchall()
        with conn:
            conn.execute(
                "update offers set delivered_at = ? where target = ? and state = 'offered'"
                " and delivered_at is null",
                (now_iso(), caller.identity),
            )
    return [offer_from_row(r) for r in [*assigned, *open_offers]]


# ----- offers --------------------------------------------------------------------------


def _check_room_url(conn: sqlite3.Connection, room_url: str) -> str:
    try:
        url = canonical_url(room_url)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"bad room_url: {e}") from e
    for (base,) in conn.execute("select url from endpoints where scope = 'roomsd'"):
        prefix = base + "/v1/rooms/"
        if url.startswith(prefix) and ROOM_ID_RE.match(url[len(prefix) :]):
            return url
    raise HTTPException(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "room_url must be a room on an approved roomsd endpoint",
    )


def _check_target(conn: sqlite3.Connection, settings, target: str) -> None:
    name, sep, domain = target.rpartition("@")
    known = (
        sep
        and domain == settings.domain
        and conn.execute(
            "select 1 from api_keys where name = ? and scope = 'agent' and revoked_at is null",
            (name,),
        ).fetchone()
    )
    if not known:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no agent {target!r} in this lobby")


@router.post("/offers", status_code=status.HTTP_201_CREATED)
def create_offer(
    req: OfferCreate, response: Response, conn: Conn, caller: Caller, settings: SettingsDep
) -> Offer:
    """Offer room work to a named agent. Retrying with the same offer_id is idempotent."""
    require_scope(caller, "agent")
    room_url = _check_room_url(conn, req.room_url)
    _check_target(conn, settings, req.to)
    if req.to == caller.identity:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "cannot offer work to yourself")
    offer_id = req.offer_id or new_id("off")
    now = now_iso()
    with conn:
        conn.execute("begin immediate")
        existing = conn.execute("select * from offers where offer_id = ?", (offer_id,)).fetchone()
        if existing:
            same = (
                existing["requester"] == caller.identity
                and existing["target"] == req.to
                and existing["room_url"] == room_url
                and existing["task"] == req.task
            )
            if not same:
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "offer_id is already used for a different offer"
                )
            response.status_code = status.HTTP_200_OK
            return offer_from_row(existing)
        conn.execute(
            "insert into offers (offer_id, requester, target, room_url, task, issue, role,"
            " scope_json, budget_json, deadline, state, created_at, updated_at)"
            " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'offered', ?, ?)",
            (
                offer_id,
                caller.identity,
                req.to,
                room_url,
                req.task,
                req.issue,
                req.role,
                json.dumps(req.scope) if req.scope is not None else None,
                json.dumps(req.budget) if req.budget is not None else None,
                iso_in(req.deadline_seconds) if req.deadline_seconds else None,
                now,
                now,
            ),
        )
        db.audit(conn, caller.identity, "offer.create", offer_id=offer_id, to=req.to)
    row = conn.execute("select * from offers where offer_id = ?", (offer_id,)).fetchone()
    return offer_from_row(row)


@router.get("/offers")
def list_offers(
    conn: Conn,
    caller: Caller,
    state: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[Offer]:
    """Offers the caller made or received."""
    require_scope(caller, "agent")
    _expire_offers(conn)
    sql = "select * from offers where (requester = ? or target = ?)"
    params: list = [caller.identity, caller.identity]
    if state:
        sql += " and state = ?"
        params.append(state)
    rows = conn.execute(sql + " order by created_at desc limit ?", [*params, limit]).fetchall()
    return [offer_from_row(r) for r in rows]


@router.get("/offers/{offer_id}")
def get_offer(offer_id: str, conn: Conn, caller: Caller) -> Offer:
    require_scope(caller, "agent")
    _expire_offers(conn)
    return offer_from_row(_offer_or_404(conn, offer_id, caller))


@router.post("/offers/{offer_id}/accept")
def accept_offer(
    offer_id: str, req: OfferTransition, conn: Conn, caller: Caller
) -> TransitionResult:
    peer = _own_live_instance(conn, caller, req.instance_id)
    _expire_offers(conn)
    with conn:
        conn.execute("begin immediate")
        row = _offer_or_404(conn, offer_id, caller)
        if row["target"] != caller.identity:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only the target can accept")
        if row["state"] in ACTIVE_STATES and row["assigned_instance"] == req.instance_id:
            return _result(conn, offer_id, changed=False)
        if row["state"] != "offered":
            raise _conflict(row, "accept")
        if peer["availability"] == "draining":
            raise HTTPException(status.HTTP_409_CONFLICT, "instance is draining")
        if _active_count(conn, req.instance_id) >= peer["max_assignments"]:
            raise HTTPException(status.HTTP_409_CONFLICT, "instance is at max_assignments")
        _set_state(conn, offer_id, "offered", "accepted", assigned_instance=req.instance_id)
        db.audit(
            conn, caller.identity, "offer.accept", offer_id=offer_id, instance_id=req.instance_id
        )
        return _result(conn, offer_id, changed=True)


@router.post("/offers/{offer_id}/decline")
def decline_offer(
    offer_id: str, req: OfferTransition, conn: Conn, caller: Caller
) -> TransitionResult:
    _own_live_instance(conn, caller, req.instance_id)
    _expire_offers(conn)
    with conn:
        conn.execute("begin immediate")
        row = _offer_or_404(conn, offer_id, caller)
        if row["target"] != caller.identity:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only the target can decline")
        if row["state"] == "declined":
            return _result(conn, offer_id, changed=False)
        if row["state"] != "offered":
            raise _conflict(row, "decline")
        _set_state(conn, offer_id, "offered", "declined", decline_reason=req.reason)
        db.audit(conn, caller.identity, "offer.decline", offer_id=offer_id)
        return _result(conn, offer_id, changed=True)


@router.post("/offers/{offer_id}/progress")
def progress_offer(
    offer_id: str, req: OfferProgress, conn: Conn, caller: Caller
) -> TransitionResult:
    """Move an accepted offer forward. Reporting the current state again returns
    changed=false: the peer must only start work when changed is true."""
    _own_live_instance(conn, caller, req.instance_id)
    with conn:
        conn.execute("begin immediate")
        row = _offer_or_404(conn, offer_id, caller)
        if row["assigned_instance"] != req.instance_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "offer is not assigned to this instance")
        current = row["state"]
        if current == req.state:
            return _result(conn, offer_id, changed=False)
        if current not in PROGRESS_ORDER or PROGRESS_ORDER[req.state] <= PROGRESS_ORDER[current]:
            raise _conflict(row, f"move to {req.state}")
        if not _set_state(conn, offer_id, current, req.state):
            raise _conflict(row, f"move to {req.state}")
        db.audit(conn, caller.identity, f"offer.{req.state}", offer_id=offer_id)
        return _result(conn, offer_id, changed=True)


@router.post("/offers/{offer_id}/cancel")
def cancel_offer(offer_id: str, conn: Conn, caller: Caller) -> TransitionResult:
    require_scope(caller, "agent")
    _expire_offers(conn)
    with conn:
        conn.execute("begin immediate")
        row = _offer_or_404(conn, offer_id, caller)
        if row["requester"] != caller.identity:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only the requester can cancel")
        if row["state"] == "cancelled":
            return _result(conn, offer_id, changed=False)
        if row["state"] not in ("offered", *ACTIVE_STATES):
            raise _conflict(row, "cancel")
        _set_state(conn, offer_id, row["state"], "cancelled")
        db.audit(conn, caller.identity, "offer.cancel", offer_id=offer_id)
        return _result(conn, offer_id, changed=True)
