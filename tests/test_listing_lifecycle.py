"""Regression tests for room-o-matic/docs#19: listings follow the server's registration
through migration, deletion, lapses and directory replacement."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from lobbyd import db

OLD, NEW = "https://old.test", "https://new.test"


@pytest.fixture
def server(make_key, approve):
    key = make_key("rooms-a", "roomsd")
    approve("rooms-a", OLD)
    approve("rooms-a", NEW)  # an alias the operator approved for migration
    return key


def register(client, key, base):
    r = client.put("/v1/servers/roomsd/rooms-a", json={"base_url": base}, headers=key)
    assert r.status_code == 200, r.text
    return r.json()


def list_room(client, key, base, room="room_x"):
    return client.put(
        "/v1/rooms", json={"room_url": f"{base}/v1/rooms/{room}", "name": room}, headers=key
    )


def search(client, headers):
    return [r["room_url"] for r in client.get("/v1/rooms", headers=headers).json()]


def test_heartbeats_keep_the_registration_and_report_listings(client, server):
    first = register(client, server, OLD)
    list_room(client, server, OLD)
    again = register(client, server, OLD)
    assert again["registration_id"] == first["registration_id"]
    assert again["listed_rooms"] == 1


def test_migration_retires_old_prefix_listings(client, server, boostie):
    first = register(client, server, OLD)
    list_room(client, server, OLD)
    moved = register(client, server, NEW)
    assert moved["registration_id"] != first["registration_id"]
    assert moved["listed_rooms"] == 0  # roomsd sees it must republish
    assert search(client, boostie) == []
    list_room(client, server, NEW)
    assert search(client, boostie) == [f"{NEW}/v1/rooms/room_x"]


def test_delete_then_reregister_does_not_resurrect(client, server, boostie):
    register(client, server, OLD)
    list_room(client, server, OLD)
    client.delete("/v1/servers/roomsd/rooms-a", headers=server)
    register(client, server, OLD)  # same id, same endpoint, new registration
    assert search(client, boostie) == []


def test_temporary_lapse_keeps_listings(client, settings, server, boostie):
    first = register(client, server, OLD)
    list_room(client, server, OLD)
    conn = db.connect(settings.db_path)
    with conn:
        conn.execute("update roomsd_servers set expires_at = '2000-01-01T00:00:00.000Z'")
    conn.close()
    assert search(client, boostie) == []  # hidden while lapsed
    back = register(client, server, OLD)
    assert back["registration_id"] == first["registration_id"]
    assert search(client, boostie) == [f"{OLD}/v1/rooms/room_x"]  # recovered unchanged


def test_foreign_prefix_rows_are_never_shown(client, settings, server, boostie):
    reg = register(client, server, OLD)["registration_id"]
    conn = db.connect(settings.db_path)
    with conn:
        conn.execute(
            "insert into listed_rooms (room_url, server_id, registration_id, name, tags_json,"
            " updated_at) values ('https://elsewhere.test/v1/rooms/room_z', 'rooms-a', ?,"
            " 'z', '[]', 'now')",
            (reg,),
        )
    conn.close()
    assert search(client, boostie) == []


def test_concurrent_migration_and_listing(client, server, boostie):
    register(client, server, OLD)
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(lambda i: list_room(client, server, OLD, f"room_{i}"), range(8)))
        register(client, server, NEW)
    # Whatever interleaving happened, nothing under the old prefix is advertised.
    assert all(url.startswith(NEW) for url in search(client, boostie))
