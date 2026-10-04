"""Signing-key ids must work as CLI arguments. A base64url kid starts with "-" about 1 in
64 times; `lobbyd signing-key retire <kid>` then failed (argparse read it as an option),
which surfaced as a rare SystemExit(2) flake in test_operations."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lobbyd import cli, db, signing


def test_new_kids_never_start_with_a_dash():
    kids = [signing._kid(Ed25519PrivateKey.generate()) for _ in range(2000)]
    assert all(k[0] == "k" for k in kids)


def test_an_older_dash_kid_can_still_be_retired(client, settings, monkeypatch):
    monkeypatch.setenv("LOBBYD_DATA_DIR", str(settings.data_dir))
    conn = db.connect(settings.db_path)
    try:
        signing.rotate(conn, lead_seconds=0)
        with conn:  # a kid minted before the prefix existed
            conn.execute("update signing_keys set kid = '-legacyKid12' where rowid = 1")
    finally:
        conn.close()
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["signing-key", "retire", "-legacyKid12"])
    assert cli.main(["signing-key", "retire", "--force", "--", "-legacyKid12"]) == 0
