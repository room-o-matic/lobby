"""Tests for room-o-matic/docs#24 (lobbyd): versioned schema, private backups, restore that
can't revive revoked keys, tenants or signing keys, and readiness/metrics. Every drill runs
on a disposable copy under tmp_path."""

import hashlib
import sqlite3
import stat

import pytest
from fastapi.testclient import TestClient

from lobbyd import apikeys, cli, db, ops, recovery
from lobbyd.app import create_app
from lobbyd.verify import InvalidToken, TokenVerifier

ROOMS_A = "https://rooms-a.test"


def sql(settings, query, params=()):
    conn = sqlite3.connect(settings.db_path)
    try:
        with conn:
            return conn.execute(query, params).fetchall()
    finally:
        conn.close()


def version_of(path):
    return sqlite3.connect(path).execute("pragma user_version").fetchone()[0]


def token(client, headers):
    return client.post("/v1/token", json={"audience": ROOMS_A}, headers=headers)


def verifier_for(client):
    return TokenVerifier(
        issuer="http://lobby.test",
        domain="test",
        audience=ROOMS_A,
        fetch_jwks=lambda: client.get("/.well-known/jwks.json").json(),
        background=lambda fn: fn(),
    )


def test_fresh_database_is_versioned(client, settings):
    assert version_of(settings.db_path) == db.SCHEMA_VERSION


def test_newer_schema_refused_untouched(client, settings):
    sql(settings, "pragma user_version = 5")
    before = hashlib.sha256(settings.db_path.read_bytes()).hexdigest()
    with pytest.raises(ops.SchemaError, match="newer than this release"):
        create_app(settings)
    assert hashlib.sha256(settings.db_path.read_bytes()).hexdigest() == before


def test_pre_baseline_schema_refused(settings):
    settings.data_dir.mkdir(parents=True)
    sql(settings, "create table api_keys (key_hash text primary key, name text)")
    with pytest.raises(ops.SchemaError, match="api_keys"):
        create_app(settings)


def test_backup_holds_keys_privately(client, settings, tmp_path):
    manifest = recovery.backup(settings, tmp_path / "bk")
    assert stat.S_IMODE((tmp_path / "bk").stat().st_mode) == 0o700
    for f in [*manifest["files"], "manifest.json"]:
        assert stat.S_IMODE((tmp_path / "bk" / f).stat().st_mode) == 0o600
    copy = sqlite3.connect(tmp_path / "bk" / "lobbyd.sqlite")
    assert copy.execute("select count(*) from signing_keys").fetchone()[0] == 1
    copy.close()


def test_restore_never_revives_revoked_access(
    client, settings, make_key, approve, rooms_a, tmp_path, monkeypatch
):
    monkeypatch.setenv("LOBBYD_DATA_DIR", str(settings.data_dir))
    alice, bob = make_key("alice"), make_key("bob")
    conn = db.connect(settings.db_path)
    apikeys.create_tenant(conn, "acme")
    acme_key = apikeys.create_key(conn, "carol", "agent", tenant_id="acme")
    conn.close()
    carol = {"Authorization": f"Bearer {acme_key}"}
    old = token(client, alice).json()["access_token"]
    assert (
        client.put(
            "/v1/servers/roomsd/rooms-a", headers=rooms_a, json={"base_url": ROOMS_A}
        ).status_code
        == 200
    )
    sql(
        settings,
        "insert into offers (offer_id, requester, target, room_url, task, state,"
        " created_at, updated_at) values ('off_1', 'bob@test', 'dave@test', ?, 't',"
        " 'offered', 'x', 'x')",
        (f"{ROOMS_A}/v1/rooms/r",),
    )
    old_kids = {k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]}
    last_audit = sql(settings, "select max(id) from audit")[0][0] or 0

    recovery.backup(settings, tmp_path / "bk")

    # after the snapshot, through the operator CLI (which journals)
    assert cli.main(["key", "revoke", "alice"]) == 0
    assert cli.main(["tenant", "disable", "acme"]) == 0
    assert cli.main(["signing-key", "rotate", "--now"]) == 0
    for kid in old_kids:  # say the old key was compromised
        assert cli.main(["signing-key", "retire", kid, "--force"]) == 0

    report = recovery.restore(settings, tmp_path / "bk", force=True)
    inv = report["invalidated"]
    assert report["integrity"] == "ok" and report["moved_aside"]
    assert inv["journal_entries_replayed"] == 2 and inv["signing_keys_retired"] == 1
    assert inv["leases_dropped"] >= 1 and inv["offers_expired"] == 1

    r = TestClient(create_app(settings))
    assert token(r, alice).status_code == 401  # revocation replayed
    assert token(r, carol).status_code == 401  # tenant stays disabled
    assert token(r, bob).status_code == 200  # untouched access still works
    kids = {k["kid"] for k in r.get("/.well-known/jwks.json").json()["keys"]}
    assert kids and not kids & old_kids  # no restored key is published or signs
    with pytest.raises(InvalidToken):
        verifier_for(r).verify(old)
    verifier_for(r).verify(token(r, bob).json()["access_token"])
    assert r.get("/v1/servers/roomsd", headers=bob).json() == []  # leases re-established
    assert sql(settings, "select state from offers")[0][0] == "expired"
    assert sql(settings, "select max(id) from audit")[0][0] > last_audit + 1000


def test_restore_refuses_wrong_service_and_existing_data(client, settings, tmp_path):
    recovery.backup(settings, tmp_path / "bk")
    with pytest.raises(ops.BackupError, match="--force"):
        recovery.restore(settings, tmp_path / "bk")
    ops.backup(settings.db_path, tmp_path / "rooms", service="roomsd")
    with pytest.raises(ops.BackupError, match="not lobbyd"):
        recovery.restore(settings, tmp_path / "rooms", force=True)


def test_cli_drill(client, settings, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LOBBYD_DATA_DIR", str(settings.data_dir))
    assert cli.main(["backup", "--out", str(tmp_path / "bk")]) == 0
    assert cli.main(["verify-backup", str(tmp_path / "bk")]) == 0
    assert cli.main(["restore", str(tmp_path / "bk"), "--force"]) == 0
    assert '"integrity": "ok"' in capsys.readouterr().out


def test_readyz_and_metrics(client, settings):
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"]["signing"]["active_keys"] == 1
    assert "lobbyd_ready 1" in client.get("/metrics").text
    sql(settings, "update signing_keys set retired_at = 'x'")
    r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["signing"]["ok"] is False
