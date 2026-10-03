"""Ed25519 signing keys, JWKS publication, and access-token issuance.

The newest unretired key signs. Every unretired key is published in the JWKS, so after
`rotate` the previous key keeps verifying tokens it already signed. Retire it once at
least one access-token lifetime has passed.
"""

import base64
import hashlib
import sqlite3
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lobbyd.ids import new_id, now_iso

ALGORITHM = "EdDSA"


def _kid(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:12]).decode().rstrip("=")


def rotate(conn: sqlite3.Connection) -> str:
    """Create a new signing key; it becomes the active one. Returns its kid."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    kid = _kid(key)
    with conn:
        conn.execute(
            "insert into signing_keys (kid, private_pem, created_at) values (?, ?, ?)",
            (kid, pem, now_iso()),
        )
    return kid


def retire(conn: sqlite3.Connection, kid: str) -> bool:
    with conn:
        cur = conn.execute(
            "update signing_keys set retired_at = ? where kid = ? and retired_at is null",
            (now_iso(), kid),
        )
    return cur.rowcount == 1


def ensure_key(conn: sqlite3.Connection) -> None:
    if conn.execute("select 1 from signing_keys where retired_at is null").fetchone() is None:
        rotate(conn)


def _active(conn: sqlite3.Connection) -> tuple[str, Ed25519PrivateKey]:
    row = conn.execute(
        "select kid, private_pem from signing_keys where retired_at is null"
        " order by created_at desc, rowid desc limit 1"
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
    return jwt.encode(claims, key, algorithm=ALGORITHM, headers={"kid": kid}), claims
