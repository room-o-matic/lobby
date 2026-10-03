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
            "select kid, created_at, retired_at from signing_keys order by created_at"
        ).fetchall()
    finally:
        conn.close()
    for r in rows:
        state = f"retired {r['retired_at']}" if r["retired_at"] else "active"
        print(f"{r['kid']}  created {r['created_at']}  {state}")
    return 0


def cmd_signing_rotate(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        print(signing.rotate(conn))
    finally:
        conn.close()
    return 0


def cmd_signing_retire(args: argparse.Namespace) -> int:
    conn = _conn()
    try:
        live = conn.execute(
            "select count(*) from signing_keys where retired_at is null and kid != ?", (args.kid,)
        ).fetchone()[0]
        if live == 0:
            print("error: refusing to retire the only active key; rotate first", file=sys.stderr)
            return 2
        if not signing.retire(conn, args.kid):
            print(f"error: no active key {args.kid!r}", file=sys.stderr)
            return 1
    finally:
        conn.close()
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
    sk_sub.add_parser("rotate", help="create a new active key").set_defaults(
        func=cmd_signing_rotate
    )
    retire = sk_sub.add_parser("retire", help="stop publishing a key (after one token TTL)")
    retire.add_argument("kid")
    retire.set_defaults(func=cmd_signing_retire)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
