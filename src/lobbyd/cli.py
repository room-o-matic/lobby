import argparse
import json
import sqlite3
import sys
from pathlib import Path

from lobbyd import apikeys, db, endpoints, ops, signing
from lobbyd.config import Settings
from lobbyd.urls import canonical_url


def _conn() -> sqlite3.Connection:
    settings = Settings.from_env()
    db.init_db(settings.db_path, backup_dir=settings.backup_dir)
    return db.connect(settings.db_path)


def _journal(kind: str, **fields) -> None:
    """docs#24: record a revocation outside the database so a restore replays it. Removals
    are journaled before they commit: a crash in between errs toward staying revoked."""
    ops.Journal(Settings.from_env().journal_path).append(kind, **fields)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("lobbyd.app:create_app", factory=True, host=args.host, port=args.port)
    return 0


def cmd_key_create(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        key = apikeys.create_key(
            conn, args.name, args.scope, tenant_id=args.tenant, label=args.label
        )
        if args.endpoint:
            if args.scope not in apikeys.HOSTED:
                raise ValueError("--endpoint is only for roomsd, agentd and service keys")
            endpoints.approve(conn, args.name, args.endpoint, max_sessions=args.max_sessions)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        conn.close()
    print(key)
    return 0


def cmd_key_revoke(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        _journal("api_key.revoke_name", name=args.name)
        n = apikeys.revoke_keys(conn, args.name)
    finally:
        conn.close()
    print(f"revoked {n} key(s) for {args.name}")
    return 0


def cmd_key_list(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        rows = conn.execute(
            "select key_id, name, scope, tenant_id, label, created_at, revoked_at"
            " from api_keys order by tenant_id, name, created_at"
        ).fetchall()
    finally:
        conn.close()
    for r in rows:
        state = f"revoked {r['revoked_at']}" if r["revoked_at"] else "active"
        label = f" [{r['label']}]" if r["label"] else ""
        print(f"{r['key_id']}  {r['tenant_id']}/{r['name']} {r['scope']}{label}  {state}")
    return 0


def cmd_key_revoke_id(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        _journal("api_key.revoke_id", key_id=args.key_id)
        ok = apikeys.revoke_key_id(conn, args.key_id)
    finally:
        conn.close()
    print(f"revoked {args.key_id}" if ok else f"error: no active key {args.key_id!r}")
    return 0 if ok else 1


def cmd_tenant_create(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        apikeys.create_tenant(conn, args.tenant_id, name=args.name, can_host=args.can_host)
    except (ValueError, sqlite3.IntegrityError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        conn.close()
    print(f"created tenant {args.tenant_id}")
    return 0


def cmd_tenant_status(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        if args.status == "disabled":
            _journal("tenant.status", tenant_id=args.tenant_id, status=args.status)
        ok = apikeys.set_tenant_status(conn, args.tenant_id, args.status)
        if ok and args.status != "disabled":
            _journal("tenant.status", tenant_id=args.tenant_id, status=args.status)
    finally:
        conn.close()
    print(f"{args.tenant_id}: {args.status}" if ok else f"error: no tenant {args.tenant_id!r}")
    return 0 if ok else 1


def cmd_tenant_grant(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        url = endpoints.grant_service(conn, args.tenant_id, args.url)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        conn.close()
    print(f"{args.tenant_id} may now use {url}")
    return 0


def cmd_endpoint_approve(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        e = endpoints.approve(
            conn,
            args.name,
            args.url,
            max_sessions=args.max_sessions,
            worker_types=args.worker_type,
        )
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    finally:
        conn.close()
    print(f"approved {e['url']} for {e['name']} ({e['scope']}, max_sessions {e['max_sessions']})")
    return 0


def cmd_endpoint_revoke(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        _journal("endpoint.revoke", url=canonical_url(args.url))
        n = endpoints.revoke(conn, args.url)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    finally:
        conn.close()
    print(f"revoked {n} endpoint(s)")
    return 0 if n else 1


def cmd_endpoint_list(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        rows = conn.execute("select * from endpoints order by name, url").fetchall()
    finally:
        conn.close()
    for r in rows:
        types = r["worker_types_json"] or "any worker type"
        print(
            f"{r['name']:<20} {r['scope']:<7} {r['url']}  max_sessions={r['max_sessions']}  {types}"
        )
    return 0


def cmd_signing_list(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        rows = conn.execute(
            "select kid, created_at, activates_at, last_issued_at, retired_at"
            " from signing_keys order by created_at"
        ).fetchall()
    finally:
        conn.close()
    for r in rows:
        if r["retired_at"]:
            state = f"retired {r['retired_at']}"
        else:
            state = f"signs from {r['activates_at']}, last issued {r['last_issued_at'] or 'never'}"
        print(f"{r['kid']}  created {r['created_at']}  {state}")
    return 0


def cmd_signing_rotate(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    lead = 0 if args.now else settings.key_publish_lead_seconds
    conn = _conn()
    try:
        kid = signing.rotate(conn, lead_seconds=lead)
    finally:
        conn.close()
    when = "now" if lead == 0 else f"in {lead}s (published now; verifiers pick it up first)"
    print(f"{kid} signs {when}")
    return 0


def cmd_signing_retire(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    conn = _conn()
    try:
        ok = signing.retire(
            conn,
            args.kid,
            min_idle_seconds=settings.access_token_ttl_seconds + settings.clock_skew_seconds,
            force=args.force,
        )
    except signing.RetireRefused as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    finally:
        conn.close()
    if not ok:
        print(f"error: no active key {args.kid!r}", file=sys.stderr)
        return 1
    print(f"retired {args.kid}")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    from lobbyd import recovery

    manifest = recovery.backup(Settings.from_env(), Path(args.out))
    print(json.dumps({k: v for k, v in manifest.items() if k != "files"}, indent=2))
    print(
        f"backed up {len(manifest['files'])} files to {args.out}. It contains private signing"
        " keys: encrypt it before it leaves this host.",
        file=sys.stderr,
    )
    return 0


def cmd_verify_backup(args: argparse.Namespace) -> int:
    try:
        manifest = ops.verify_backup(Path(args.path))
    except ops.BackupError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(
        f"ok: {manifest['service']} schema v{manifest['schema_version']},"
        f" {len(manifest['files'])} files, taken {manifest['created_at']}"
    )
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    from lobbyd import recovery

    try:
        report = recovery.restore(
            Settings.from_env(), Path(args.source), force=args.force, id_gap=args.id_gap
        )
    except (ops.BackupError, ops.SchemaError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lobbyd", description="Identity issuer and directory")
    sub = p.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the HTTP server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8767)
    serve.set_defaults(func=cmd_serve)

    key = sub.add_parser("key", help="manage API keys (local DB access)")
    key_sub = key.add_subparsers(dest="key_command", required=True)
    create = key_sub.add_parser("create", help="issue an API key and print it")
    create.add_argument("name", help="agent name, agentd instance_id, or roomsd server_id")
    create.add_argument("--scope", choices=apikeys.SCOPES, default="agent")
    create.add_argument("--tenant", default="internal", help="owning tenant (default internal)")
    create.add_argument("--label", help="which deployment holds this credential")
    create.add_argument("--endpoint", help="roomsd/agentd/service: also approve this base URL")
    create.add_argument("--max-sessions", type=int, help="agentd: approved capacity cap")
    create.set_defaults(func=cmd_key_create)
    revoke = key_sub.add_parser("revoke", help="revoke all keys for a name")
    revoke.add_argument("name")
    revoke.set_defaults(func=cmd_key_revoke)
    key_sub.add_parser("list", help="list keys by tenant").set_defaults(func=cmd_key_list)
    revoke_id = key_sub.add_parser("revoke-id", help="revoke one credential by key id")
    revoke_id.add_argument("key_id")
    revoke_id.set_defaults(func=cmd_key_revoke_id)

    tenant = sub.add_parser("tenant", help="owners: create, disable/enable, grant services")
    tenant_sub = tenant.add_subparsers(dest="tenant_command", required=True)
    t_create = tenant_sub.add_parser("create")
    t_create.add_argument("tenant_id")
    t_create.add_argument("--name")
    t_create.add_argument(
        "--can-host", action="store_true", help="may hold roomsd/agentd (service) keys"
    )
    t_create.set_defaults(func=cmd_tenant_create)
    for status in ("disable", "enable"):
        t = tenant_sub.add_parser(status, help=f"{status} every key of the tenant")
        t.add_argument("tenant_id")
        t.set_defaults(
            func=cmd_tenant_status, status="disabled" if status == "disable" else "active"
        )
    t_grant = tenant_sub.add_parser("grant", help="let a tenant use a service endpoint")
    t_grant.add_argument("tenant_id")
    t_grant.add_argument("url")
    t_grant.set_defaults(func=cmd_tenant_grant)

    ep = sub.add_parser("endpoint", help="approve service endpoints (roomsd/agentd/service)")
    ep_sub = ep.add_subparsers(dest="ep_command", required=True)
    approve = ep_sub.add_parser("approve", help="approve a base URL for a roomsd/agentd key")
    approve.add_argument("name")
    approve.add_argument("url")
    approve.add_argument("--max-sessions", type=int, help="agentd capacity cap (default 64)")
    approve.add_argument(
        "--worker-type", action="append", help="agentd: allowed worker type (repeatable)"
    )
    approve.set_defaults(func=cmd_endpoint_approve)
    ep_revoke = ep_sub.add_parser("revoke", help="withdraw approval and drop registrations")
    ep_revoke.add_argument("url")
    ep_revoke.set_defaults(func=cmd_endpoint_revoke)
    ep_sub.add_parser("list").set_defaults(func=cmd_endpoint_list)

    sk = sub.add_parser("signing-key", help="manage token signing keys")
    sk_sub = sk.add_subparsers(dest="sk_command", required=True)
    sk_sub.add_parser("list").set_defaults(func=cmd_signing_list)
    rotate = sk_sub.add_parser(
        "rotate", help="publish a new key now; it signs after the publish lead"
    )
    rotate.add_argument("--now", action="store_true", help="emergency: sign immediately")
    rotate.set_defaults(func=cmd_signing_rotate)
    retire = sk_sub.add_parser(
        "retire", help="stop publishing a key once its last token has expired"
    )
    retire.add_argument(
        "kid",
        help="as `signing-key list` shows it (an older kid starting with '-': retire -- <kid>)",
    )
    retire.add_argument(
        "--force", action="store_true", help="emergency: retire now (compromised key)"
    )
    retire.set_defaults(func=cmd_signing_retire)

    # docs#24: operate on $LOBBYD_DATA_DIR directly (stop the server before restoring).
    b = sub.add_parser("backup", help="consistent snapshot of the database (safe while serving)")
    b.add_argument("--out", required=True, help="new directory to write the backup into")
    b.set_defaults(func=cmd_backup)
    v = sub.add_parser("verify-backup", help="check a backup's checksums and integrity")
    v.add_argument("path")
    v.set_defaults(func=cmd_verify_backup)
    r = sub.add_parser("restore", help="restore a backup into $LOBBYD_DATA_DIR (server stopped)")
    r.add_argument("source", help="backup directory")
    r.add_argument("--force", action="store_true", help="move an existing database aside")
    r.add_argument(
        "--id-gap", type=int, default=1_000_000, help="advance audit IDs past the snapshot"
    )
    r.set_defaults(func=cmd_restore)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
