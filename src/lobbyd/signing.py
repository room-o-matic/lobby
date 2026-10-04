"""Ed25519 signing keys, JWKS publication, and access-token issuance.

Rotation contract (room-o-matic/docs#6):
- `rotate` publishes a new key in the JWKS immediately but it only starts signing at
  `activates_at` (now + publish lead), after verifiers' caches have refreshed. `--now`
  activates at once for emergencies, and unknown-kid fetches cover the gap.
- The most recently created unretired key that has activated signs, so an emergency
  `rotate --now` keeps signing even after an earlier pending key activates. Every
  unretired key is published.
- `retire` refuses until the key's last issued token has expired (TTL + clock skew), unless
  forced. Forced (emergency) retirement takes effect at each verifier's next successful
  JWKS fetch, and fails closed after the verifier's max stale age.
"""

import base64
import hashlib
import sqlite3
import time
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lobbyd.ids import iso_in, new_id, now_iso

ALGORITHM = "EdDSA"


def _kid(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # Prefixed so a kid never starts with "-": about 1 in 64 base64url ids did, and the CLI
    # (`signing-key retire <kid>`) then read the kid as an option and failed.
    return "k" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:12]).decode().rstrip("=")


def rotate(conn: sqlite3.Connection, *, lead_seconds: int = 0) -> str:
    """Create a new signing key, published now and signing from now + lead_seconds."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    kid = _kid(key)
    with conn:
        conn.execute(
            "insert into signing_keys (kid, private_pem, created_at, activates_at)"
            " values (?, ?, ?, ?)",
            (kid, pem, now_iso(), iso_in(lead_seconds)),
        )
    return kid


class RetireRefused(Exception):
    pass


def retire(
    conn: sqlite3.Connection, kid: str, *, min_idle_seconds: int = 0, force: bool = False
) -> bool:
    """Stop publishing `kid`. Unless forced, refuse while it is the only key that can sign,
    or while tokens it issued in the last `min_idle_seconds` may still be valid."""
    row = conn.execute(
        "select * from signing_keys where kid = ? and retired_at is null", (kid,)
    ).fetchone()
    if row is None:
        return False
    if not force:
        others = conn.execute(
            "select count(*) from signing_keys where retired_at is null and kid != ?", (kid,)
        ).fetchone()[0]
        if others == 0:
            raise RetireRefused("refusing to retire the only key; rotate first")
        if row["last_issued_at"]:
            last = datetime.fromisoformat(row["last_issued_at"])
            safe_at = last + timedelta(seconds=min_idle_seconds)
            if datetime.now(UTC) < safe_at:
                raise RetireRefused(
                    f"tokens signed by {kid} may be valid until {safe_at.isoformat()};"
                    " retire after that, or force it in an emergency"
                )
    with conn:
        conn.execute("update signing_keys set retired_at = ? where kid = ?", (now_iso(), kid))
    return True


def ensure_key(conn: sqlite3.Connection) -> None:
    """Bootstrap: with no usable key, create one that signs immediately."""
    if conn.execute("select 1 from signing_keys where retired_at is null").fetchone() is None:
        rotate(conn, lead_seconds=0)


def _active(conn: sqlite3.Connection) -> tuple[str, Ed25519PrivateKey]:
    row = conn.execute(
        "select kid, private_pem from signing_keys where retired_at is null"
        " and activates_at <= ? order by created_at desc, rowid desc limit 1",
        (now_iso(),),
    ).fetchone()
    if row is None:
        raise RuntimeError("no active signing key; run `lobbyd signing-key rotate`")
    return row["kid"], serialization.load_pem_private_key(row["private_pem"].encode(), None)


def jwks(conn: sqlite3.Connection) -> dict:
    keys = []
    for row in conn.execute(
        "select kid, private_pem from signing_keys where retired_at is null order by created_at"
    ):
        public = serialization.load_pem_private_key(row["private_pem"].encode(), None).public_key()
        jwk = jwt.algorithms.OKPAlgorithm.to_jwk(public, as_dict=True)
        keys.append({**jwk, "kid": row["kid"], "use": "sig", "alg": ALGORITHM})
    return {"keys": keys}


def issue(
    conn: sqlite3.Connection,
    *,
    issuer: str,
    subject: str,
    audience: str,
    scope: str,
    ttl_seconds: int,
    tenant: str | None = None,
) -> tuple[str, dict]:
    kid, key = _active(conn)
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "scope": scope,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": new_id("tok"),
    }
    if tenant:
        claims["tenant"] = tenant  # receiving services may scope grants by it (docs#11)
    with conn:
        conn.execute("update signing_keys set last_issued_at = ? where kid = ?", (now_iso(), kid))
    return jwt.encode(claims, key, algorithm=ALGORITHM, headers={"kid": kid}), claims
