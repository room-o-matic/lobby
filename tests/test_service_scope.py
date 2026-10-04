"""The `service` key scope: an operator-approved endpoint for a service that only
authenticates its callers (e.g. dispatchd's operator API). Found live: lobbyd refused to
mint operator tokens for dispatchd because only roomsd/agentd keys could own endpoints."""

import pytest

from lobbyd import apikeys, cli, db

DISPATCH = "https://dispatch.test"


@pytest.fixture
def service(client, settings, make_key, approve):
    headers = make_key("dispatchd", "service")
    approve("dispatchd", DISPATCH)
    return headers


def token(client, headers, audience=DISPATCH):
    return client.post("/v1/token", json={"audience": audience}, headers=headers)


def test_agents_get_tokens_for_an_approved_service(client, service, boostie):
    r = token(client, boostie)
    assert r.status_code == 200 and r.json()["audience"] == DISPATCH
    assert r.json()["scope"] == "agent"


def test_the_service_key_itself_is_inert(client, service):
    r = token(client, service)
    assert r.status_code == 403 and "don't exchange tokens" in r.json()["detail"]
    body = {"base_url": DISPATCH}
    assert client.put("/v1/servers/roomsd/dispatchd", json=body, headers=service).status_code == 403
    assert (
        client.put(
            "/v1/registry/agentd/dispatchd",
            headers=service,
            json={
                "base_url": DISPATCH,
                "worker_types": ["fake"],
                "profiles": ["p"],
                "max_sessions": 1,
            },
        ).status_code
        == 403
    )


def test_a_service_endpoint_is_not_in_the_directory(client, service, boostie):
    assert client.get("/v1/servers/roomsd", headers=boostie).json() == []
    assert client.get("/v1/registry/agentd", headers=boostie).json() == []


def test_service_keys_need_a_hosting_tenant(client, settings):
    conn = db.connect(settings.db_path)
    try:
        apikeys.create_tenant(conn, "acme")
        with pytest.raises(ValueError, match="may not hold service"):
            apikeys.create_key(conn, "acme-dispatch", "service", tenant_id="acme")
    finally:
        conn.close()


def test_cli_creates_and_approves_in_one_step(client, settings, monkeypatch, capsys):
    monkeypatch.setenv("LOBBYD_DATA_DIR", str(settings.data_dir))
    assert (
        cli.main(
            [
                "key",
                "create",
                "dispatchd",
                "--scope",
                "service",
                "--endpoint",
                "https://Dispatch.test/",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.startswith("lbk_")
    conn = db.connect(settings.db_path)
    try:
        row = conn.execute(
            "select name, scope from endpoints where url = ?", (DISPATCH,)
        ).fetchone()
    finally:
        conn.close()
    assert tuple(row) == ("dispatchd", "service")
