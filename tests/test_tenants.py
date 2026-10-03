"""Regression tests for room-o-matic/docs#11: tenants, cross-tenant isolation in the
directory, service grants, revocation, and budgets."""

import jwt
import pytest
from fastapi.testclient import TestClient

from lobbyd import apikeys, db, endpoints
from lobbyd.app import create_app
from lobbyd.limits import AuditPruner

ROOMS_A = "https://rooms-a.test"


@pytest.fixture
def acme(settings, client):
    conn = db.connect(settings.db_path)
    apikeys.create_tenant(conn, "acme", name="Acme")
    conn.close()


@pytest.fixture
def internal_world(client, rooms_a, agentd1, boostie):
    client.put("/v1/servers/roomsd/rooms-a", json={"base_url": ROOMS_A}, headers=rooms_a)
    client.put(
        "/v1/rooms",
        json={"room_url": f"{ROOMS_A}/v1/rooms/room_1", "name": "internal"},
        headers=rooms_a,
    )
    client.put(
        "/v1/registry/agentd/agentd-host1",
        json={"base_url": "http://host1:8765", "worker_types": ["fake"], "max_sessions": 2},
        headers=agentd1,
    )


def test_no_cross_tenant_discovery_or_tokens(client, acme, internal_world, make_key, boostie):
    bob = make_key("bob", tenant_id="acme")
    assert client.get("/v1/servers/roomsd", headers=bob).json() == []
    assert client.get("/v1/rooms", headers=bob).json() == []
    assert client.get("/v1/registry/agentd", headers=bob).json() == []
    assert client.get("/v1/registry/agentd/agentd-host1", headers=bob).status_code == 404
    r = client.post("/v1/token", json={"audience": ROOMS_A}, headers=bob)
    assert r.status_code == 403
    # internal agents see their own tenant's directory as before
    assert len(client.get("/v1/servers/roomsd", headers=boostie).json()) == 1


def test_service_grant_opens_one_endpoint(client, settings, acme, internal_world, make_key):
    bob = make_key("bob", tenant_id="acme")
    conn = db.connect(settings.db_path)
    endpoints.grant_service(conn, "acme", ROOMS_A)
    conn.close()
    assert [s["server_id"] for s in client.get("/v1/servers/roomsd", headers=bob).json()] == [
        "rooms-a"
    ]
    assert [r["name"] for r in client.get("/v1/rooms", headers=bob).json()] == ["internal"]
    tok = client.post("/v1/token", json={"audience": ROOMS_A}, headers=bob).json()
    claims = jwt.decode(tok["access_token"], options={"verify_signature": False})
    assert claims["tenant"] == "acme"
    # only that endpoint: the agentd instance stays invisible
    assert client.get("/v1/registry/agentd", headers=bob).json() == []


def test_peers_and_offers_stay_inside_a_tenant(client, acme, internal_world, make_key, boostie):
    bob = make_key("bob", tenant_id="acme")
    client.put("/v1/peers/bob-s1", json={}, headers=bob)
    client.put("/v1/peers/boostie-s1", json={}, headers=boostie)
    assert [p["principal"] for p in client.get("/v1/peers", headers=bob).json()] == ["bob@test"]
    room = f"{ROOMS_A}/v1/rooms/room_1"
    r = client.post(
        "/v1/offers", json={"to": "boostie@test", "room_url": room, "task": "t"}, headers=bob
    )
    assert r.status_code in (404, 422)  # unknown agent / not a room it can see
    r = client.post(
        "/v1/offers", json={"to": "bob@test", "room_url": room, "task": "t"}, headers=boostie
    )
    assert r.status_code == 404  # other tenant's agent looks unknown


def test_identity_reservation_and_service_scopes(settings, client, acme, boostie):
    conn = db.connect(settings.db_path)
    try:
        with pytest.raises(ValueError, match="reserved by tenant 'internal'"):
            apikeys.create_key(conn, "boostie", "agent", tenant_id="acme")
        with pytest.raises(ValueError, match="may not hold service"):
            apikeys.create_key(conn, "acme-rooms", "roomsd", tenant_id="acme")
        with pytest.raises(ValueError, match="no tenant"):
            apikeys.create_key(conn, "x", "agent", tenant_id="nope")
    finally:
        conn.close()


def test_disabled_tenant_keys_stop_working(client, settings, acme, make_key):
    bob = make_key("bob", tenant_id="acme")
    assert client.get("/v1/whoami", headers=bob).status_code == 200
    conn = db.connect(settings.db_path)
    apikeys.set_tenant_status(conn, "acme", "disabled")
    conn.close()
    assert client.get("/v1/whoami", headers=bob).status_code == 401
    conn = db.connect(settings.db_path)
    apikeys.set_tenant_status(conn, "acme", "active")
    conn.close()
    assert client.get("/v1/whoami", headers=bob).status_code == 200


def test_per_credential_revocation(client, settings, make_key):
    laptop = make_key("boostie", label="laptop")
    server = make_key("boostie", label="server")
    who = client.get("/v1/whoami", headers=laptop).json()
    assert who["identity"] == "boostie@test"
    conn = db.connect(settings.db_path)
    key_id = conn.execute("select key_id from api_keys where label = 'laptop'").fetchone()[0]
    assert apikeys.revoke_key_id(conn, key_id)
    conn.close()
    assert client.get("/v1/whoami", headers=laptop).status_code == 401
    assert client.get("/v1/whoami", headers=server).status_code == 200


def tight(settings, **kw):
    return TestClient(create_app(settings.__class__(**{**settings.__dict__, **kw})))


def test_token_exchange_rate_limit_is_per_key(settings, client, make_key, approve):
    make_key("rooms-a", "roomsd")
    approve("rooms-a", ROOMS_A)
    flood, internal = make_key("flooder"), make_key("boostie")
    c = tight(settings, token_rate_per_minute=3)
    codes = [
        c.post("/v1/token", json={"audience": ROOMS_A}, headers=flood).status_code for _ in range(4)
    ]
    assert codes == [200, 200, 200, 429]
    r = c.post("/v1/token", json={"audience": ROOMS_A}, headers=flood)
    assert int(r.headers["retry-after"]) >= 1
    # another key isn't starved by the flood
    assert c.post("/v1/token", json={"audience": ROOMS_A}, headers=internal).status_code == 200


def test_metadata_is_capped(client, rooms_a):
    big = {"blob": "x" * (256 * 1024)}
    r = client.put(
        "/v1/servers/roomsd/rooms-a", json={"base_url": ROOMS_A, "metadata": big}, headers=rooms_a
    )
    assert r.status_code == 422


def test_listing_budget(settings, client, rooms_a):
    c = tight(settings, max_listed_rooms_per_server=2)
    c.put("/v1/servers/roomsd/rooms-a", json={"base_url": ROOMS_A}, headers=rooms_a)
    for i in (1, 2):
        body = {"room_url": f"{ROOMS_A}/v1/rooms/room_{i}", "name": f"r{i}"}
        assert c.put("/v1/rooms", json=body, headers=rooms_a).status_code == 200
    third = {"room_url": f"{ROOMS_A}/v1/rooms/room_3", "name": "r3"}
    assert c.put("/v1/rooms", json=third, headers=rooms_a).status_code == 429
    again = {"room_url": f"{ROOMS_A}/v1/rooms/room_1", "name": "renamed"}
    assert c.put("/v1/rooms", json=again, headers=rooms_a).status_code == 200  # updates fine


def test_peer_and_offer_budgets(settings, client, make_key, approve):
    make_key("rooms-a", "roomsd")
    approve("rooms-a", ROOMS_A)
    boostie = make_key("boostie")
    make_key("odin")  # the offer target must exist
    c = tight(settings, max_peer_instances=2, max_open_offers=2)
    assert [c.put(f"/v1/peers/s{i}", json={}, headers=boostie).status_code for i in range(3)] == [
        200,
        200,
        429,
    ]
    room = f"{ROOMS_A}/v1/rooms/room_1"
    codes = [
        c.post(
            "/v1/offers",
            json={"to": "odin@test", "room_url": room, "task": f"t{i}"},
            headers=boostie,
        ).status_code
        for i in range(3)
    ]
    assert codes == [201, 201, 429]


def test_directory_pagination(client, make_key, approve, boostie):
    for i in range(5):
        key = make_key(f"rooms-{i}", "roomsd")
        approve(f"rooms-{i}", f"https://rooms-{i}.test")
        client.put(
            f"/v1/servers/roomsd/rooms-{i}",
            json={"base_url": f"https://rooms-{i}.test"},
            headers=key,
        )
    page1 = client.get("/v1/servers/roomsd", params={"limit": 2}, headers=boostie).json()
    page2 = client.get(
        "/v1/servers/roomsd", params={"limit": 2, "after": page1[-1]["server_id"]}, headers=boostie
    ).json()
    assert [s["server_id"] for s in page1 + page2] == [f"rooms-{i}" for i in range(4)]


def test_audit_retention(settings, client):
    conn = db.connect(settings.db_path)
    with conn:
        conn.execute(
            "insert into audit (actor, action, created_at)"
            " values ('x', 'old', '2000-01-01T00:00:00.000Z')"
        )
    assert AuditPruner(retention_days=30, interval_seconds=0).maybe_prune(conn) >= 1
    assert conn.execute("select count(*) from audit where action = 'old'").fetchone()[0] == 0
    conn.close()
