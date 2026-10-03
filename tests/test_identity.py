import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lobbyd import apikeys, db, signing
from lobbyd.verify import InvalidToken, TokenVerifier

ROOMS_A = "https://rooms-a.test"


def get_token(client, headers, audience=ROOMS_A):
    r = client.post("/v1/token", json={"audience": audience}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def verifier(client, audience=ROOMS_A, **kw):
    return TokenVerifier(
        issuer="http://lobby.test",
        domain="test",
        audience=audience,
        fetch_jwks=lambda: client.get("/.well-known/jwks.json").json(),
        **kw,
    )


def test_well_known(client):
    wk = client.get("/.well-known/lobbyd").json()
    assert wk == {
        "issuer": "http://lobby.test",
        "domain": "test",
        "jwks_uri": "http://lobby.test/.well-known/jwks.json",
        "token_endpoint": "http://lobby.test/v1/token",
        "access_token_ttl_seconds": 900,
    }
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "OKP" and keys[0]["crv"] == "Ed25519" and keys[0]["alg"] == "EdDSA"
    assert "d" not in keys[0]  # never publish the private part


def test_token_round_trip(client, boostie):
    tok = get_token(client, boostie, ROOMS_A + "/")
    assert tok["identity"] == "boostie@test"
    assert tok["audience"] == ROOMS_A  # trailing slash normalised
    claims = verifier(client).verify(tok["access_token"])
    assert (claims.identity, claims.name, claims.scope) == ("boostie@test", "boostie", "agent")
    assert claims.expires_at == tok["expires_at"]


def test_token_requires_valid_key(client):
    r = client.post("/v1/token", json={"audience": ROOMS_A})
    assert r.status_code == 401
    r = client.post(
        "/v1/token", json={"audience": ROOMS_A}, headers={"Authorization": "Bearer lbk_x"}
    )
    assert r.status_code == 401


def test_revoked_key_cannot_get_tokens(client, settings, boostie):
    conn = db.connect(settings.db_path)
    apikeys.revoke_keys(conn, "boostie")
    conn.close()
    assert client.post("/v1/token", json={"audience": ROOMS_A}, headers=boostie).status_code == 401


def test_audience_must_be_url(client, boostie):
    r = client.post("/v1/token", json={"audience": "rooms-a"}, headers=boostie)
    assert r.status_code == 422


def test_wrong_audience_rejected(client, boostie):
    tok = get_token(client, boostie, "https://rooms-b.test")["access_token"]
    with pytest.raises(InvalidToken, match="[Aa]udience"):
        verifier(client).verify(tok)


def test_wrong_issuer_or_domain_rejected(client, boostie):
    tok = get_token(client, boostie)["access_token"]
    other_issuer = TokenVerifier(
        issuer="http://evil.test",
        domain="test",
        audience=ROOMS_A,
        fetch_jwks=lambda: client.get("/.well-known/jwks.json").json(),
    )
    with pytest.raises(InvalidToken, match="[Ii]ssuer"):
        other_issuer.verify(tok)
    other_domain = TokenVerifier(
        issuer="http://lobby.test",
        domain="elsewhere",
        audience=ROOMS_A,
        fetch_jwks=lambda: client.get("/.well-known/jwks.json").json(),
    )
    with pytest.raises(InvalidToken, match="not in domain"):
        other_domain.verify(tok)


def test_expired_token_rejected(client, settings):
    conn = db.connect(settings.db_path)
    try:
        tok, _ = signing.issue(
            conn,
            issuer="http://lobby.test",
            subject="boostie@test",
            audience=ROOMS_A,
            scope="agent",
            ttl_seconds=-120,
        )
    finally:
        conn.close()
    with pytest.raises(InvalidToken, match="expired"):
        verifier(client).verify(tok)


def test_tampered_and_foreign_tokens_rejected(client, boostie):
    tok = get_token(client, boostie)["access_token"]
    head, body, sig = tok.split(".")
    flipped = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
    with pytest.raises(InvalidToken):
        verifier(client).verify(f"{head}.{body}.{flipped}")

    kid = jwt.get_unverified_header(tok)["kid"]
    forged = jwt.encode(
        {**jwt.decode(tok, options={"verify_signature": False}), "sub": "missy@test"},
        Ed25519PrivateKey.generate(),
        algorithm="EdDSA",
        headers={"kid": kid},
    )
    with pytest.raises(InvalidToken):
        verifier(client).verify(forged)
    with pytest.raises(InvalidToken, match="malformed"):
        verifier(client).verify("not-a-jwt")


def test_rotation_keeps_old_tokens_valid_until_retired(client, settings, boostie):
    v = verifier(client, min_refresh_seconds=0)
    old = get_token(client, boostie)["access_token"]
    v.verify(old)

    conn = db.connect(settings.db_path)
    old_kid = jwt.get_unverified_header(old)["kid"]
    new_kid = signing.rotate(conn)
    conn.close()

    new = get_token(client, boostie)["access_token"]
    assert jwt.get_unverified_header(new)["kid"] == new_kid
    v.verify(new)  # unknown kid triggers a JWKS refetch
    v.verify(old)

    conn = db.connect(settings.db_path)
    signing.retire(conn, old_kid)
    conn.close()
    fresh = verifier(client)
    fresh.verify(new)
    with pytest.raises(InvalidToken, match="unknown signing key"):
        fresh.verify(old)


def test_jwks_refetch_is_rate_limited(client, boostie):
    calls = []

    def fetch():
        calls.append(time.monotonic())
        return client.get("/.well-known/jwks.json").json()

    v = TokenVerifier(issuer="http://lobby.test", domain="test", audience=ROOMS_A, fetch_jwks=fetch)
    tok = get_token(client, boostie)["access_token"]
    v.verify(tok)
    bogus = jwt.encode({"sub": "x@test"}, "k" * 32, algorithm="HS256", headers={"kid": "nope"})
    for _ in range(5):
        with pytest.raises(InvalidToken):
            v.verify(bogus)
    assert len(calls) == 1


def test_whoami_and_audit(client, settings, boostie):
    assert client.get("/v1/whoami", headers=boostie).json() == {
        "name": "boostie",
        "identity": "boostie@test",
        "scope": "agent",
    }
    get_token(client, boostie)
    conn = db.connect(settings.db_path)
    rows = conn.execute("select actor, action from audit").fetchall()
    conn.close()
    assert [tuple(r) for r in rows] == [("boostie@test", "token.issue")]


def test_name_cannot_span_scopes(settings, boostie):
    conn = db.connect(settings.db_path)
    try:
        with pytest.raises(ValueError, match="already has 'agent' keys"):
            apikeys.create_key(conn, "boostie", "roomsd")
    finally:
        conn.close()


def test_data_dir_is_private(settings, client):
    assert (settings.data_dir.stat().st_mode & 0o777) == 0o700
