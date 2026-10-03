"""Regression tests for room-o-matic/docs#5: directory entries are bound to operator-
approved endpoints, listings can't be taken over, and capacity claims are bounded."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from lobbyd import db, endpoints
from lobbyd.urls import canonical_url


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("HTTP://Rooms-A.Test:80/", "http://rooms-a.test"),
        ("https://rooms-a.test:443", "https://rooms-a.test"),
        ("https://rooms-a.test:8443/prefix/", "https://rooms-a.test:8443/prefix"),
        ("http://127.0.0.1:8766", "http://127.0.0.1:8766"),  # local dev stays allowed
        ("http://[::1]:8766", "http://[::1]:8766"),
    ],
)
def test_canonical_url(raw, canonical):
    assert canonical_url(raw) == canonical


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://rooms-a.test",
        "https://user:pw@rooms-a.test",
        "https://evil.test@rooms-a.test",
        "https://rooms-a.test/?x=1",
        "https://rooms-a.test/#frag",
        "https://rooms-a.test/a/../b",
        "https://rooms-a.test/./a",
        "https://rooms-a.test//a",
        "https://rooms-a.test/%2e%2e",
        "https://rooms-a.test\\@evil.test",
        "https:///nohost",
        "https://rooms-a.test:99999",
    ],
)
def test_canonical_url_rejects(bad):
    with pytest.raises(ValueError):
        canonical_url(bad)


def reg_server(client, headers, server_id, base_url):
    return client.put(
        f"/v1/servers/roomsd/{server_id}", json={"base_url": base_url}, headers=headers
    )


def test_registration_requires_approved_endpoint(client, make_key, approve):
    key = make_key("rooms-x", "roomsd")
    assert reg_server(client, key, "rooms-x", "https://rooms-x.test").status_code == 403
    approve("rooms-x", "https://rooms-x.test")
    r = reg_server(client, key, "rooms-x", "HTTPS://ROOMS-X.test:443/")  # equivalent spelling
    assert r.status_code == 200
    assert r.json()["base_url"] == "https://rooms-x.test"


def test_cannot_register_another_owners_endpoint(client, rooms_a, make_key, approve):
    """The issue's takeover: rooms-b adopts rooms-a's URL."""
    b = make_key("rooms-b", "roomsd")
    with pytest.raises(ValueError, match="already approved for 'rooms-a'"):
        approve("rooms-b", "HTTPS://rooms-a.test/")  # URL-equivalent duplicate
    assert reg_server(client, b, "rooms-b", "https://rooms-a.test").status_code == 403


def test_aliases_under_one_owner(client, rooms_a, approve):
    approve("rooms-a", "https://rooms-a-alias.test")
    assert reg_server(client, rooms_a, "rooms-a", "https://rooms-a-alias.test").status_code == 200


def test_endpoint_change_needs_new_approval(client, rooms_a, approve):
    assert reg_server(client, rooms_a, "rooms-a", "https://rooms-a.test").status_code == 200
    assert reg_server(client, rooms_a, "rooms-a", "https://elsewhere.test").status_code == 403


def test_revoking_endpoint_drops_registration(client, settings, rooms_a, boostie):
    reg_server(client, rooms_a, "rooms-a", "https://rooms-a.test")
    conn = db.connect(settings.db_path)
    assert endpoints.revoke(conn, "https://rooms-a.test") == 1
    conn.close()
    assert client.get("/v1/servers/roomsd", headers=boostie).json() == []
    assert reg_server(client, rooms_a, "rooms-a", "https://rooms-a.test").status_code == 403


def test_listing_takeover_rejected(client, rooms_a, make_key, approve):
    reg_server(client, rooms_a, "rooms-a", "https://rooms-a.test")
    room = {"room_url": "https://rooms-a.test/v1/rooms/room_1", "name": "a"}
    assert client.put("/v1/rooms", json=room, headers=rooms_a).status_code == 200
    b = make_key("rooms-b", "roomsd")
    approve("rooms-b", "https://rooms-b.test")
    reg_server(client, b, "rooms-b", "https://rooms-b.test")
    # rooms-b can't list a URL under rooms-a's endpoint, by prefix or by equivalent spelling
    for url in [room["room_url"], "HTTPS://rooms-a.test:443/v1/rooms/room_1"]:
        assert client.put("/v1/rooms", json={**room, "room_url": url}, headers=b).status_code == 403


def test_listing_upsert_is_owner_guarded_even_if_prefix_check_is_bypassed(
    client, settings, rooms_a
):
    """Direct check of the atomic guard: a row owned by another server is never replaced."""
    reg_server(client, rooms_a, "rooms-a", "https://rooms-a.test")
    conn = db.connect(settings.db_path)
    with conn:
        conn.execute(
            "insert into listed_rooms (room_url, server_id, name, tags_json, updated_at)"
            " values ('https://rooms-a.test/v1/rooms/room_9', 'someone-else', 'x', '[]', 'now')"
        )
    conn.close()
    r = client.put(
        "/v1/rooms",
        json={"room_url": "https://rooms-a.test/v1/rooms/room_9", "name": "mine"},
        headers=rooms_a,
    )
    assert r.status_code == 409


def test_concurrent_listing_upserts_keep_one_owner(client, rooms_a):
    reg_server(client, rooms_a, "rooms-a", "https://rooms-a.test")
    body = {"room_url": "https://rooms-a.test/v1/rooms/room_1", "name": "a"}
    with ThreadPoolExecutor(8) as pool:
        codes = list(
            pool.map(
                lambda _: client.put("/v1/rooms", json=body, headers=rooms_a).status_code, range(16)
            )
        )
    assert set(codes) == {200}


def test_room_url_must_be_a_room_under_the_endpoint(client, rooms_a):
    reg_server(client, rooms_a, "rooms-a", "https://rooms-a.test")
    for url in [
        "https://rooms-a.test/v1/rooms/room_1/extra",
        "https://rooms-a.test/v1/rooms/",
        "https://rooms-a.test/v1/registry/agentd",
    ]:
        r = client.put("/v1/rooms", json={"room_url": url, "name": "a"}, headers=rooms_a)
        assert r.status_code in (403, 422), url


def agentd_body(**kw):
    return {"base_url": "http://host1:8765", "worker_types": ["fake"], "max_sessions": 4, **kw}


def test_forged_capacity_rejected(client, agentd1):
    r = client.put(
        "/v1/registry/agentd/agentd-host1",
        json=agentd_body(max_sessions=10**12),
        headers=agentd1,
    )
    assert r.status_code == 422
    r = client.put(
        "/v1/registry/agentd/agentd-host1", json=agentd_body(max_sessions=65), headers=agentd1
    )
    assert r.status_code == 422  # over the approved default cap of 64
    r = client.put(
        "/v1/registry/agentd/agentd-host1",
        json=agentd_body(active_sessions=9),
        headers=agentd1,
    )
    assert r.status_code == 422


def test_worker_types_bounded_by_approval(client, make_key, approve):
    key = make_key("agentd-x", "agentd")
    approve("agentd-x", "http://x:8765", worker_types=["fake"], max_sessions=2)
    ok = agentd_body(base_url="http://x:8765", max_sessions=2)
    assert client.put("/v1/registry/agentd/agentd-x", json=ok, headers=key).status_code == 200
    bad = {**ok, "worker_types": ["fake", "claude"]}
    r = client.put("/v1/registry/agentd/agentd-x", json=bad, headers=key)
    assert r.status_code == 422 and "claude" in r.json()["detail"]


def test_instance_cannot_claim_another_instances_endpoint(client, agentd1, make_key, boostie):
    """The issue's forged-capacity selection attack: second identity advertises the real
    instance's endpoint."""
    evil = make_key("agentd-evil", "agentd")
    r = client.put("/v1/registry/agentd/agentd-evil", json=agentd_body(), headers=evil)
    assert r.status_code == 403
    found = client.get("/v1/registry/agentd", headers=boostie).json()
    assert all(i["instance_id"] != "agentd-evil" for i in found)


def test_tokens_only_for_approved_audiences(client, boostie, rooms_a):
    ok = client.post("/v1/token", json={"audience": "https://rooms-a.test/"}, headers=boostie)
    assert ok.status_code == 200 and ok.json()["audience"] == "https://rooms-a.test"
    r = client.post("/v1/token", json={"audience": "https://attacker.test"}, headers=boostie)
    assert r.status_code == 403
    r = client.post("/v1/token", json={"audience": "https://x@rooms-a.test"}, headers=boostie)
    assert r.status_code == 422


def test_endpoint_approval_rules(settings, make_key, boostie):
    conn = db.connect(settings.db_path)
    try:
        with pytest.raises(ValueError, match="no live roomsd/agentd key"):
            endpoints.approve(conn, "boostie", "https://x.test")
        make_key("agentd-y", "agentd")
        with pytest.raises(ValueError, match="max_sessions"):
            endpoints.approve(conn, "agentd-y", "https://y.test", max_sessions=10**6)
    finally:
        conn.close()
