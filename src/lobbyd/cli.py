import argparse
import sqlite3
import sys

from lobbyd import apikeys, db, endpoints, signing
from lobbyd.config import Settings


def _conn() -> sqlite3.Connection:
    settings = Settings.from_env()
    db.init_db(settings.db_path)
    return db.connect(settings.db_path)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("lobbyd.app:create_app", factory=True, host=args.host, port=args.port)
    return 0


def cmd_key_create(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        key = apikeys.create_key(conn, args.name, args.scope)
        if args.endpoint:
            if args.scope not in ("roomsd", "agentd"):
                raise ValueError("--endpoint is only for roomsd/agentd keys")
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
        n = apikeys.revoke_keys(conn, args.name)
    finally:
        conn.close()
    print(f"revoked {n} key(s) for {args.name}")
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
    create.add_argument("--endpoint", help="roomsd/agentd: also approve this base URL")
    create.add_argument("--max-sessions", type=int, help="agentd: approved capacity cap")
    create.set_defaults(func=cmd_key_create)
    revoke = key_sub.add_parser("revoke", help="revoke all keys for a name")
    revoke.add_argument("name")
    revoke.set_defaults(func=cmd_key_revoke)

    ep = sub.add_parser("endpoint", help="approve service endpoints (roomsd/agentd)")
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
    retire.add_argument("kid")
    retire.add_argument(
        "--force", action="store_true", help="emergency: retire now (compromised key)"
    )
    retire.set_defaults(func=cmd_signing_retire)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
