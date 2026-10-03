from lobbyd import db


def expire(settings, table, key_col, key):
    conn = db.connect(settings.db_path)
    with conn:
        conn.execute(
            f"update {table} set expires_at = '2000-01-01T00:00:00.000Z' where {key_col} = ?",
            (key,),
        )
    conn.close()


def agentd_reg(**kw):
    return {
        "base_url": "http://host1:8765",
        "worker_types": ["codex", "fake"],
        "profiles": ["workspace_coder"],
        "max_sessions": 4,
        "active_sessions": 1,
        **kw,
    }


def register_rooms_a(client, rooms_a, **kw):
    body = {"base_url": "https://rooms-a.test/", "tags": ["project=alpha"], **kw}
    return client.put("/v1/servers/roomsd/rooms-a", json=body, headers=rooms_a)


# ----- roomsd servers ---------------------------------------------------------------


def test_server_register_and_list(client, rooms_a, boostie):
    r = register_rooms_a(client, rooms_a)
    assert r.status_code == 200
    assert r.json()["base_url"] == "https://rooms-a.test"
    servers = client.get("/v1/servers/roomsd", headers=boostie).json()
    assert [s["server_id"] for s in servers] == ["rooms-a"]
    assert client.get("/v1/servers/roomsd", params={"tag": "nope"}, headers=boostie).json() == []


def test_server_can_only_manage_itself(client, rooms_a, make_key, approve, boostie):
    make_key("rooms-b", "roomsd")
    approve("rooms-b", "https://rooms-b.test")
    body = {"base_url": "https://rooms-b.test"}
    assert client.put("/v1/servers/roomsd/rooms-b", json=body, headers=rooms_a).status_code == 403
    assert client.put("/v1/servers/roomsd/boostie", json=body, headers=boostie).status_code == 403


def test_server_lease_expires_and_deregisters(client, settings, rooms_a, boostie):
    register_rooms_a(client, rooms_a)
    expire(settings, "roomsd_servers", "server_id", "rooms-a")
    assert client.get("/v1/servers/roomsd", headers=boostie).json() == []
    register_rooms_a(client, rooms_a)
    assert client.delete("/v1/servers/roomsd/rooms-a", headers=rooms_a).status_code == 204
    assert client.get("/v1/servers/roomsd", headers=boostie).json() == []


def test_lease_ttl_capped(client, rooms_a):
    assert register_rooms_a(client, rooms_a, ttl_seconds=10_000).status_code == 422


# ----- agentd registry --------------------------------------------------------------


def test_agentd_register_heartbeat_lookup(client, agentd1, boostie):
    first = client.put("/v1/registry/agentd/agentd-host1", json=agentd_reg(), headers=agentd1)
    assert first.status_code == 200
    again = client.put(
        "/v1/registry/agentd/agentd-host1", json=agentd_reg(active_sessions=3), headers=agentd1
    ).json()
    assert again["registered_at"] == first.json()["registered_at"]
    assert again["available_sessions"] == 1

    found = client.get(
        "/v1/registry/agentd",
        params={"worker_type": "codex", "has_capacity": True},
        headers=boostie,
    ).json()
    assert [i["instance_id"] for i in found] == ["agentd-host1"]
    assert client.get("/v1/registry/agentd/agentd-host1", headers=agentd1).status_code == 200


def test_agentd_scope_rules(client, agentd1, boostie, rooms_a):
    assert (
        client.put("/v1/registry/agentd/boostie", json=agentd_reg(), headers=boostie).status_code
        == 403
    )
    assert client.get("/v1/registry/agentd", headers=agentd1).status_code == 403
    assert client.get("/v1/registry/agentd", headers=rooms_a).status_code == 403


def test_agentd_ordering_and_expiry(client, settings, make_key, approve, boostie):
    for name, body in {
        "h-busy": agentd_reg(base_url="http://busy:8765", max_sessions=2, active_sessions=2),
        "h-roomy": agentd_reg(base_url="http://roomy:8765", max_sessions=8, active_sessions=1),
    }.items():
        headers = make_key(name, "agentd")
        approve(name, body["base_url"])
        client.put(f"/v1/registry/agentd/{name}", json=body, headers=headers)
    ids = [i["instance_id"] for i in client.get("/v1/registry/agentd", headers=boostie).json()]
    assert ids == ["h-roomy", "h-busy"]
    expire(settings, "agentd_instances", "instance_id", "h-roomy")
    ids = [i["instance_id"] for i in client.get("/v1/registry/agentd", headers=boostie).json()]
    assert ids == ["h-busy"]


# ----- listed rooms -----------------------------------------------------------------


def listing(**kw):
    return {
        "room_url": "https://rooms-a.test/v1/rooms/room_01ABC",
        "name": "release-factory",
        "purpose": "Design the 100%_release testing factory",
        "tags": ["project=alpha"],
        **kw,
    }


def test_list_and_search_rooms(client, rooms_a, boostie):
    register_rooms_a(client, rooms_a)
    r = client.put("/v1/rooms", json=listing(), headers=rooms_a)
    assert r.status_code == 200
    assert r.json()["server_id"] == "rooms-a"

    def search(**params):
        rooms = client.get("/v1/rooms", params=params, headers=boostie).json()
        return [x["name"] for x in rooms]

    assert search() == ["release-factory"]
    assert search(q="testing") == ["release-factory"]
    assert search(q="100%_r") == ["release-factory"]
    assert search(q="100%x") == []  # % and _ are literal, not wildcards
    assert search(tag="project=alpha", server_id="rooms-a") == ["release-factory"]
    assert search(tag="project=beta") == []


def test_server_must_be_registered_to_list(client, rooms_a):
    assert client.put("/v1/rooms", json=listing(), headers=rooms_a).status_code == 409


def test_server_cannot_list_foreign_room_urls(client, rooms_a):
    register_rooms_a(client, rooms_a)
    for url in [
        "https://rooms-b.test/v1/rooms/room_x",
        "https://rooms-a.test.evil/v1/rooms/room_x",
        "https://rooms-a.test/v1/registry/agentd",
    ]:
        r = client.put("/v1/rooms", json=listing(room_url=url), headers=rooms_a)
        assert r.status_code == 403, url


def test_only_roomsd_can_list(client, rooms_a, boostie):
    register_rooms_a(client, rooms_a)
    assert client.put("/v1/rooms", json=listing(), headers=boostie).status_code == 403


def test_rooms_hidden_when_server_lapses(client, settings, rooms_a, boostie):
    register_rooms_a(client, rooms_a)
    client.put("/v1/rooms", json=listing(), headers=rooms_a)
    expire(settings, "roomsd_servers", "server_id", "rooms-a")
    assert client.get("/v1/rooms", headers=boostie).json() == []


def test_unlist_only_own(client, rooms_a, make_key, boostie):
    register_rooms_a(client, rooms_a)
    client.put("/v1/rooms", json=listing(), headers=rooms_a)
    rooms_b = make_key("rooms-b", "roomsd")  # no endpoint needed to attempt a delete
    url = listing()["room_url"]
    client.delete("/v1/rooms", params={"room_url": url}, headers=rooms_b)
    assert len(client.get("/v1/rooms", headers=boostie).json()) == 1
    client.delete("/v1/rooms", params={"room_url": url}, headers=rooms_a)
    assert client.get("/v1/rooms", headers=boostie).json() == []


def test_request_connection_can_change_threads(settings, client):
    """Regression: see roomsd; FastAPI moves a request's connection between threads."""
    import threading

    conn = db.connect(settings.db_path)
    result = []
    t = threading.Thread(target=lambda: result.append(conn.execute("select 1").fetchone()[0]))
    t.start()
    t.join()
    conn.close()
    assert result == [1]
