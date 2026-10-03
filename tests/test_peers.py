"""Tests for room-o-matic/docs#7: named peers register sessions and receive room-work
offers through a durable inbox, separate from spawning workers."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from lobbyd import db

ROOM = "https://rooms-a.test/v1/rooms/room_1"


@pytest.fixture
def world(client, make_key, approve):
    make_key("rooms-a", "roomsd")
    approve("rooms-a", "https://rooms-a.test")
    return {
        "missy": make_key("missy"),  # the requester
        "odin": make_key("odin"),
        "boostie": make_key("boostie"),
    }


def register(client, headers, instance, **kw):
    r = client.put(f"/v1/peers/{instance}", json=kw, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def offer(client, headers, to, **kw):
    return client.post(
        "/v1/offers", json={"to": to, "room_url": ROOM, "task": "review", **kw}, headers=headers
    )


def act(client, headers, offer_id, verb, instance, **kw):
    return client.post(
        f"/v1/offers/{offer_id}/{verb}", json={"instance_id": instance, **kw}, headers=headers
    )


def inbox(client, headers, instance):
    return client.get(f"/v1/peers/{instance}/inbox", headers=headers)


def test_two_named_peers_decline_then_accept_and_reconnect(client, world):
    """The issue's end-to-end scenario, lobby side."""
    odin, boostie, missy = world["odin"], world["boostie"], world["missy"]
    register(client, odin, "odin-s1", capabilities=["review"])
    register(client, boostie, "boostie-s1", capabilities=["review"])
    peers = client.get("/v1/peers", params={"capability": "review"}, headers=missy).json()
    assert {p["principal"] for p in peers} == {"odin@test", "boostie@test"}

    o1 = offer(client, missy, "odin@test", offer_id="issue-7:odin").json()
    assert [o["offer_id"] for o in inbox(client, odin, "odin-s1").json()] == [o1["offer_id"]]
    assert inbox(client, boostie, "boostie-s1").json() == []  # not addressed to boostie
    r = act(client, odin, o1["offer_id"], "decline", "odin-s1", reason="busy with release")
    assert r.json()["offer"]["state"] == "declined"
    assert client.get(f"/v1/offers/{o1['offer_id']}", headers=missy).json()["decline_reason"] == (
        "busy with release"
    )

    o2 = offer(client, missy, "boostie@test", offer_id="issue-7:boostie").json()
    accepted = act(client, boostie, o2["offer_id"], "accept", "boostie-s1").json()
    assert accepted["changed"] and accepted["offer"]["assigned_instance"] == "boostie-s1"
    joined = act(client, boostie, o2["offer_id"], "progress", "boostie-s1", state="joined")
    assert joined.json()["changed"]
    start = act(client, boostie, o2["offer_id"], "progress", "boostie-s1", state="working")
    assert start.json()["changed"] is True  # first report: do the work

    # Reconnect: the session re-registers and re-polls; the assignment is still there...
    register(client, boostie, "boostie-s1", capabilities=["review"])
    again = inbox(client, boostie, "boostie-s1").json()
    assert [(o["offer_id"], o["state"]) for o in again] == [(o2["offer_id"], "working")]
    # ...and re-reporting "working" says not to start it a second time.
    dup = act(client, boostie, o2["offer_id"], "progress", "boostie-s1", state="working")
    assert dup.json()["changed"] is False

    done = act(client, boostie, o2["offer_id"], "progress", "boostie-s1", state="completed")
    assert done.json()["offer"]["state"] == "completed"
    assert inbox(client, boostie, "boostie-s1").json() == []


def test_offer_id_is_idempotent(client, world):
    first = offer(client, world["missy"], "odin@test", offer_id="once")
    again = offer(client, world["missy"], "odin@test", offer_id="once")
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json()["offer_id"] == "once"
    clash = offer(client, world["missy"], "odin@test", offer_id="once", task="different")
    assert clash.status_code == 409


def test_sessions_of_one_principal_are_distinct(client, world):
    odin = world["odin"]
    register(client, odin, "odin-a")
    register(client, odin, "odin-b")
    o = offer(client, world["missy"], "odin@test").json()
    assert act(client, odin, o["offer_id"], "accept", "odin-a").json()["changed"]
    # The other session can't accept or drive it: one execution identity per assignment.
    assert act(client, odin, o["offer_id"], "accept", "odin-b").status_code == 409
    r = act(client, odin, o["offer_id"], "progress", "odin-b", state="working")
    assert r.status_code == 403
    assert inbox(client, odin, "odin-b").json() == []
    assert [x["offer_id"] for x in inbox(client, odin, "odin-a").json()] == [o["offer_id"]]


def test_instance_ids_belong_to_one_agent(client, world):
    register(client, world["odin"], "shared-id")
    r = client.put("/v1/peers/shared-id", json={}, headers=world["boostie"])
    assert r.status_code == 403
    assert inbox(client, world["boostie"], "shared-id").status_code == 404


def test_draining_and_busy_are_distinct(client, world):
    odin, missy = world["odin"], world["missy"]
    register(client, odin, "odin-s1", availability="draining")
    o = offer(client, missy, "odin@test").json()
    assert inbox(client, odin, "odin-s1").json() == []  # draining: no new offers shown
    assert act(client, odin, o["offer_id"], "accept", "odin-s1").status_code == 409

    register(client, odin, "odin-s1", availability="busy", max_assignments=1)
    assert [x["offer_id"] for x in inbox(client, odin, "odin-s1").json()] == [o["offer_id"]]
    assert act(client, odin, o["offer_id"], "accept", "odin-s1").json()["changed"]  # its choice
    second = offer(client, missy, "odin@test").json()
    r = act(client, odin, second["offer_id"], "accept", "odin-s1")
    assert r.status_code == 409 and "max_assignments" in r.json()["detail"]
    avail = client.get("/v1/peers", params={"available": True}, headers=missy).json()
    assert all(p["instance_id"] != "odin-s1" for p in avail)


def test_heartbeat_is_not_consent(client, world):
    register(client, world["odin"], "odin-s1")
    o = offer(client, world["missy"], "odin@test").json()
    register(client, world["odin"], "odin-s1")  # heartbeats...
    register(client, world["odin"], "odin-s1")
    assert client.get(f"/v1/offers/{o['offer_id']}", headers=world["missy"]).json()["state"] == (
        "offered"
    )


def test_offline_peer_keeps_its_inbox(client, settings, world):
    register(client, world["odin"], "odin-s1")
    o = offer(client, world["missy"], "odin@test").json()
    conn = db.connect(settings.db_path)
    with conn:
        conn.execute("update peers set expires_at = '2000-01-01T00:00:00.000Z'")
    conn.close()
    assert client.get("/v1/peers", headers=world["missy"]).json() == []  # offline
    assert inbox(client, world["odin"], "odin-s1").status_code == 404  # must re-register
    register(client, world["odin"], "odin-s1")
    assert [x["offer_id"] for x in inbox(client, world["odin"], "odin-s1").json()] == [
        o["offer_id"]
    ]  # nothing lost while offline


def test_deadline_expires_unanswered_offers(client, settings, world):
    register(client, world["odin"], "odin-s1")
    o = offer(client, world["missy"], "odin@test", deadline_seconds=60).json()
    conn = db.connect(settings.db_path)
    with conn:
        conn.execute("update offers set deadline = '2000-01-01T00:00:00.000Z'")
    conn.close()
    assert inbox(client, world["odin"], "odin-s1").json() == []
    r = act(client, world["odin"], o["offer_id"], "accept", "odin-s1")
    assert r.status_code == 409 and "expired" in r.json()["detail"]


def test_cancel_races_with_accept_have_one_winner(client, world):
    odin, missy = world["odin"], world["missy"]
    register(client, odin, "odin-s1", max_assignments=50)
    for _ in range(10):
        o = offer(client, missy, "odin@test").json()
        with ThreadPoolExecutor(2) as pool:
            a = pool.submit(act, client, odin, o["offer_id"], "accept", "odin-s1")
            c = pool.submit(client.post, f"/v1/offers/{o['offer_id']}/cancel", headers=missy)
            a, c = a.result(), c.result()
        final = client.get(f"/v1/offers/{o['offer_id']}", headers=missy).json()["state"]
        assert final == "cancelled"  # cancel always wins: it may cancel an accepted offer
        assert c.status_code == 200
        assert a.status_code in (200, 409)


def test_cancel_after_accept_is_visible_to_the_peer(client, world):
    odin, missy = world["odin"], world["missy"]
    register(client, odin, "odin-s1")
    o = offer(client, missy, "odin@test").json()
    act(client, odin, o["offer_id"], "accept", "odin-s1")
    client.post(f"/v1/offers/{o['offer_id']}/cancel", headers=missy)
    r = act(client, odin, o["offer_id"], "progress", "odin-s1", state="working")
    assert r.status_code == 409 and "cancelled" in r.json()["detail"]
    assert inbox(client, odin, "odin-s1").json() == []


def test_progress_only_moves_forward(client, world):
    odin = world["odin"]
    register(client, odin, "odin-s1")
    o = offer(client, world["missy"], "odin@test").json()
    act(client, odin, o["offer_id"], "accept", "odin-s1")
    act(client, odin, o["offer_id"], "progress", "odin-s1", state="working")
    assert (
        act(client, odin, o["offer_id"], "progress", "odin-s1", state="joined").status_code == 409
    )
    act(client, odin, o["offer_id"], "progress", "odin-s1", state="handed_off")
    r = act(client, odin, o["offer_id"], "progress", "odin-s1", state="completed")
    assert r.status_code == 409  # handed_off and completed are both terminal


def test_offer_validation(client, world):
    missy = world["missy"]
    assert offer(client, missy, "nobody@test").status_code == 404
    assert offer(client, missy, "odin@elsewhere").status_code == 404
    assert offer(client, missy, "missy@test").status_code == 422
    bad = offer(client, missy, "odin@test", room_url="https://evil.test/v1/rooms/room_1")
    assert bad.status_code == 422  # only rooms on approved roomsd endpoints
    o = offer(client, missy, "odin@test").json()
    assert client.get(f"/v1/offers/{o['offer_id']}", headers=world["boostie"]).status_code == 404
