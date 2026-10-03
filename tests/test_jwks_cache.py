"""Regression tests for room-o-matic/docs#6: the verifier's JWKS cache survives lobbyd
outages without hammering it, known keys never wait on the network, unknown kids are
fetched once, and rotation propagates without rejecting valid tokens."""

import threading
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lobbyd import db, signing
from lobbyd.verify import InvalidToken, TokenVerifier

ISS, DOMAIN, AUD = "http://lobby.test", "test", "https://rooms-a.test"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class KeyServer:
    """A fake JWKS endpoint: keys can be added, fetches can fail or block."""

    def __init__(self):
        self.keys: dict[str, Ed25519PrivateKey] = {}
        self.fail = False
        self.gate: threading.Event | None = None
        self.calls = 0

    def add(self, kid: str) -> str:
        self.keys[kid] = Ed25519PrivateKey.generate()
        return kid

    def jwks(self) -> dict:
        self.calls += 1
        if self.gate is not None:
            self.gate.wait(5)
        if self.fail:
            raise ConnectionError("lobbyd unreachable")
        out = []
        for kid, k in self.keys.items():
            jwk = jwt.algorithms.OKPAlgorithm.to_jwk(k.public_key(), as_dict=True)
            out.append({**jwk, "kid": kid, "alg": "EdDSA", "use": "sig"})
        return {"keys": out}

    def token(self, kid: str) -> str:
        now = int(time.time())
        claims = {
            "iss": ISS,
            "sub": f"boostie@{DOMAIN}",
            "aud": AUD,
            "scope": "agent",
            "iat": now,
            "nbf": now,
            "exp": now + 900,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self.keys[kid], algorithm="EdDSA", headers={"kid": kid})


def make(server: KeyServer, clock: Clock, **kw) -> TokenVerifier:
    kw.setdefault("background", lambda fn: fn())  # deterministic unless a test wants threads
    return TokenVerifier(
        issuer=ISS, domain=DOMAIN, audience=AUD, fetch_jwks=server.jwks, clock=clock, **kw
    )


@pytest.fixture
def server():
    s = KeyServer()
    s.add("k1")
    return s


def test_outage_does_not_turn_every_request_into_a_fetch(server):
    clock = Clock()
    v = make(server, clock)
    tok = server.token("k1")
    v.verify(tok)  # warm
    assert server.calls == 1

    server.fail = True
    clock.t += 301  # cache is now stale
    for _ in range(5):
        assert v.verify(tok).identity == "boostie@test"  # served from cache
    assert server.calls == 2  # one failed attempt, not five

    clock.t += 0.5
    v.verify(tok)
    assert server.calls == 2  # still inside the 1s failure backoff
    clock.t += 0.6
    v.verify(tok)
    assert server.calls == 3  # retried after backoff; backoff now 2s
    clock.t += 1.5
    v.verify(tok)
    assert server.calls == 3
    clock.t += 0.6
    v.verify(tok)
    assert server.calls == 4


def test_backoff_is_capped(server):
    clock = Clock()
    v = make(server, clock, backoff_max_seconds=8)
    tok = server.token("k1")
    v.verify(tok)
    server.fail = True
    clock.t += 301
    for _ in range(10):  # drive failures well past the cap
        v.verify(tok)
        clock.t += 8
    calls = server.calls
    clock.t += 8
    v.verify(tok)
    assert server.calls == calls + 1  # never waits longer than the cap


def test_recovery_resets_backoff_and_drops_retired_keys(server):
    clock = Clock()
    v = make(server, clock)
    tok1 = server.token("k1")
    v.verify(tok1)
    server.fail = True
    clock.t += 301
    v.verify(tok1)  # cache still serves k1 during the outage
    server.fail = False
    del server.keys["k1"]  # emergency retirement on the server side
    server.add("k2")
    clock.t += 1.1
    v.verify(server.token("k2"))  # unknown kid -> successful fetch replaces the key set
    clock.t += 1.1
    with pytest.raises(InvalidToken, match="unknown signing key 'k1'"):
        v.verify(tok1)


def test_cache_older_than_max_stale_fails_closed(server):
    clock = Clock()
    v = make(server, clock, max_stale_seconds=600)
    tok = server.token("k1")
    v.verify(tok)
    server.fail = True
    clock.t += 601
    with pytest.raises(InvalidToken, match="stale"):
        v.verify(tok)
    server.fail = False
    clock.t += 120  # past any backoff
    assert v.verify(tok).identity == "boostie@test"  # recovers on the next good fetch


def test_unknown_kid_is_fetched_once_per_request_and_rate_limited(server):
    clock = Clock()
    v = make(server, clock)
    v.verify(server.token("k1"))
    server.add("k2")
    server.fail = True
    tok2 = server.token("k2")
    clock.t += 1.1  # past min_refresh_seconds since the warm-up fetch
    with pytest.raises(InvalidToken):
        v.verify(tok2)
    assert server.calls == 2  # exactly one fetch for this request, not two
    for _ in range(5):
        with pytest.raises(InvalidToken):
            v.verify(tok2)
    assert server.calls == 2  # bogus/unknown kids can't hammer lobbyd during backoff


def test_emergency_rotation_right_after_a_fetch_is_bounded(server):
    """Old default: a new kid was rejected for 10s after any fetch. Now the window is
    min_refresh_seconds (1s) for the emergency path."""
    clock = Clock()
    v = make(server, clock)
    v.verify(server.token("k1"))  # cache fetched at t
    server.add("k2")  # rotate --now: signs immediately
    tok2 = server.token("k2")
    clock.t += 1.0
    assert v.verify(tok2).identity == "boostie@test"
    assert server.calls == 2


def test_publish_before_activate_needs_no_unknown_kid_fetch(server):
    """Normal rotation: the key is published at rotate time and signs only after the lead
    (> cache_seconds), so the routine stale refresh learns it before any token uses it."""
    clock = Clock()
    v = make(server, clock)
    v.verify(server.token("k1"))
    server.add("k2")  # published, not yet signing
    clock.t += 301
    v.verify(server.token("k1"))  # still k1; the stale cache refreshes and learns k2
    calls = server.calls
    clock.t += 59  # activation at the 360s lead
    v.verify(server.token("k2"))
    assert server.calls == calls  # no extra fetch was needed


def test_known_key_never_waits_on_a_slow_refresh(server):
    clock = Clock()
    v = make(server, clock, background=None)  # real background thread
    tok = server.token("k1")
    v.verify(tok)
    deadline = time.monotonic() + 5
    while v.fetches and server.calls < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    server.gate = threading.Event()  # the next fetch hangs
    clock.t += 301
    t = time.monotonic()
    for _ in range(20):
        v.verify(tok)
    assert time.monotonic() - t < 0.5
    assert v.fetches == 2  # a single background refresh, shared
    server.gate.set()


def test_concurrent_unknown_kid_callers_share_one_fetch(server):
    clock = Clock()
    v = make(server, clock, background=None)
    v.verify(server.token("k1"))
    while server.calls < 1:
        time.sleep(0.01)
    server.add("k2")
    tok2 = server.token("k2")
    clock.t += 2
    server.gate = threading.Event()
    results = []

    def call():
        try:
            results.append(v.verify(tok2).identity)
        except InvalidToken as e:
            results.append(str(e))

    threads = [threading.Thread(target=call) for _ in range(8)]
    for th in threads:
        th.start()
    time.sleep(0.2)
    server.gate.set()
    for th in threads:
        th.join(5)
    assert results == ["boostie@test"] * 8
    assert v.fetches == 2


# ----- server-side rotation contract ---------------------------------------------------


def test_rotate_publishes_before_signing(client, settings, boostie, make_key, approve):
    make_key("rooms-a", "roomsd")
    approve("rooms-a", AUD)
    conn = db.connect(settings.db_path)
    old_kid = conn.execute("select kid from signing_keys").fetchone()[0]
    new_kid = signing.rotate(conn, lead_seconds=settings.key_publish_lead_seconds)
    conn.close()

    published = {k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]}
    assert published == {old_kid, new_kid}
    tok = client.post("/v1/token", json={"audience": AUD}, headers=boostie).json()
    assert jwt.get_unverified_header(tok["access_token"])["kid"] == old_kid

    conn = db.connect(settings.db_path)
    with conn:
        conn.execute(
            "update signing_keys set activates_at = '2000-01-01T00:00:00.000Z' where kid = ?",
            (new_kid,),
        )
    conn.close()
    tok = client.post("/v1/token", json={"audience": AUD}, headers=boostie).json()
    assert jwt.get_unverified_header(tok["access_token"])["kid"] == new_kid


def test_retire_waits_for_last_issued_token(client, settings, boostie, make_key, approve):
    make_key("rooms-a", "roomsd")
    approve("rooms-a", AUD)
    conn = db.connect(settings.db_path)
    old_kid = conn.execute("select kid from signing_keys").fetchone()[0]
    client.post("/v1/token", json={"audience": AUD}, headers=boostie)  # old key signs
    signing.rotate(conn)
    idle = settings.access_token_ttl_seconds + settings.clock_skew_seconds
    with pytest.raises(signing.RetireRefused, match="may be valid until"):
        signing.retire(conn, old_kid, min_idle_seconds=idle)
    assert signing.retire(conn, old_kid, min_idle_seconds=idle, force=True)  # emergency
    conn.close()
    published = {k["kid"] for k in client.get("/.well-known/jwks.json").json()["keys"]}
    assert old_kid not in published


def test_cannot_retire_only_key(settings, client):
    conn = db.connect(settings.db_path)
    kid = conn.execute("select kid from signing_keys").fetchone()[0]
    with pytest.raises(signing.RetireRefused, match="only key"):
        signing.retire(conn, kid)
    conn.close()


def test_emergency_key_keeps_signing_after_pending_key_activates(settings, client):
    conn = db.connect(settings.db_path)
    pending = signing.rotate(conn, lead_seconds=360)
    emergency = signing.rotate(conn, lead_seconds=0)
    with conn:
        conn.execute(
            "update signing_keys set activates_at = '2000-01-01T00:00:00.000Z' where kid = ?",
            (pending,),
        )
    assert signing._active(conn)[0] == emergency
    conn.close()
