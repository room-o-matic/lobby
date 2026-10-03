"""Backup and restore for lobbyd (room-o-matic/docs#24). See ops.py for the mechanics.

lobbyd backups contain private signing keys and API key hashes: they are written 0600 in
a 0700 directory and must be encrypted before they leave the host.

A restored snapshot is older than the lobbyd it replaces. Before serving, a restore:

- retires every signing key in the snapshot and starts signing with a fresh one at once.
  A key retired (or compromised) after the snapshot can't come back, and tokens signed
  before the restore stop verifying at each verifier's next JWKS refresh; clients
  re-exchange their API keys;
- replays the revocation journal written since the snapshot started: API key revocations
  (by name or id), tenant status changes, endpoint revocations;
- drops directory leases (roomsd servers, agentd instances, listed rooms, peers). Services
  re-register within a third of their TTL; roomsd sees a new registration_id and
  republishes its listings (docs#19);
- expires offers still in 'offered', so an offer already answered after the snapshot isn't
  delivered again. Accepted and in-progress offers are kept; their rooms are the record.
- moves audit IDs past `id_gap`.
"""

import sqlite3
from pathlib import Path

from lobbyd import db, endpoints, ops, signing
from lobbyd.config import Settings
from lobbyd.ids import now_iso

DEFAULT_ID_GAP = 1_000_000
LEASE_TABLES = ["roomsd_servers", "agentd_instances", "listed_rooms", "peers"]


def backup(settings: Settings, dest: Path) -> dict:
    return ops.backup(settings.db_path, dest, service="lobbyd", schema_version=db.SCHEMA_VERSION)


def replay(conn: sqlite3.Connection, entries: list[dict]) -> int:
    n = 0
    for e in entries:
        kind = e["kind"]
        with conn:
            if kind == "api_key.revoke_name":
                conn.execute(
                    "update api_keys set revoked_at = coalesce(revoked_at, ?) where name = ?",
                    (e["at"], e["name"]),
                )
            elif kind == "api_key.revoke_id":
                conn.execute(
                    "update api_keys set revoked_at = coalesce(revoked_at, ?) where key_id = ?",
                    (e["at"], e["key_id"]),
                )
            elif kind == "tenant.status":
                conn.execute(
                    "update tenants set status = ? where tenant_id = ?",
                    (e["status"], e["tenant_id"]),
                )
            elif kind == "endpoint.revoke":
                pass  # handled below, outside this transaction
            else:
                continue
        if kind == "endpoint.revoke":
            endpoints.revoke(conn, e["url"])
        n += 1
    return n


def post_restore(conn: sqlite3.Connection, journal: ops.Journal, since: str, id_gap: int) -> dict:
    summary: dict = {}
    now = now_iso()
    with conn:
        summary["signing_keys_retired"] = conn.execute(
            "update signing_keys set retired_at = ? where retired_at is null", (now,)
        ).rowcount
    summary["signing_key"] = signing.rotate(conn, lead_seconds=0)
    summary["journal_entries_replayed"] = replay(conn, journal.entries(since=since))
    with conn:
        summary["leases_dropped"] = sum(
            conn.execute(f"delete from {t}").rowcount for t in LEASE_TABLES
        )
        summary["offers_expired"] = conn.execute(
            "update offers set state = 'expired', decline_reason = 'restored_from_backup',"
            " updated_at = ? where state = 'offered'",
            (now,),
        ).rowcount
        ops.bump_sequences(conn, ["audit"], id_gap)
        summary["id_gap"] = id_gap
        db.audit(conn, "operator", "ops.restore", **summary)
    return summary


def restore(settings: Settings, src: Path, *, force: bool = False, id_gap: int = DEFAULT_ID_GAP):
    report = ops.restore(
        src,
        settings.data_dir,
        service="lobbyd",
        max_schema_version=db.SCHEMA_VERSION,
        force=force,
    )
    report["schema"] = db.init_db(settings.db_path, backup_dir=settings.backup_dir)
    conn = db.connect(settings.db_path)
    try:
        report["invalidated"] = post_restore(
            conn, ops.Journal(settings.journal_path), report["snapshot_started_at"], id_gap
        )
    finally:
        conn.close()
    report["report_path"] = str(ops.write_report(settings.data_dir, report))
    return report
