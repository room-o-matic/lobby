import shutil

from fastapi import FastAPI, Response

from lobbyd import db, ops, signing
from lobbyd.config import Settings
from lobbyd.limits import AuditPruner, RateLimiter
from lobbyd.routes import directory, identity, peers


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    # docs#24: upgrades the schema (after a pre-upgrade backup) or refuses to start.
    db.init_db(settings.db_path, backup_dir=settings.backup_dir)
    conn = db.connect(settings.db_path)
    try:
        signing.ensure_key(conn)
    finally:
        conn.close()

    app = FastAPI(title="lobbyd", version="0.1.0")
    app.state.settings = settings
    app.state.token_limiter = RateLimiter(settings.token_rate_per_minute)
    app.state.audit_pruner = AuditPruner(settings.audit_retention_days)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    def checks() -> dict:
        """Readiness (docs#24): can lobbyd issue tokens and serve the directory?"""
        conn = db.connect(settings.db_path)
        try:
            now = ops.now()
            version = ops.read_schema_version(conn)
            keys = conn.execute(
                "select sum(activates_at <= ?), sum(activates_at > ?), count(*)"
                " from signing_keys where retired_at is null",
                (now, now),
            ).fetchone()
            expired = sum(
                conn.execute(f"select count(*) from {t} where expires_at <= ?", (now,)).fetchone()[
                    0
                ]
                for t in ("roomsd_servers", "agentd_instances", "peers")
            )
            live = {
                t: conn.execute(
                    f"select count(*) from {t} where expires_at > ?", (now,)
                ).fetchone()[0]
                for t in ("roomsd_servers", "agentd_instances", "peers")
            }
            open_offers = conn.execute(
                "select count(*) from offers where state = 'offered'"
            ).fetchone()[0]
        finally:
            conn.close()
        db_error = ops.db_writable(settings.db_path)
        free = shutil.disk_usage(settings.data_dir).free
        return {
            "database": {"ok": db_error is None, "error": db_error},
            "schema": {"ok": version == db.SCHEMA_VERSION, "version": version},
            "storage": {"ok": free >= settings.min_free_bytes, "free_bytes": free},
            "signing": {
                "ok": bool(keys[0]),
                "active_keys": keys[0] or 0,
                "pending_keys": keys[1] or 0,
                "published_keys": keys[2],
            },
            "directory": {
                "ok": True,
                "roomsd_servers": live["roomsd_servers"],
                "agentd_instances": live["agentd_instances"],
                "peers": live["peers"],
                "expired_leases": expired,
                "open_offers": open_offers,
            },
        }

    @app.get("/readyz")
    def readyz(response: Response) -> dict:
        c = checks()
        ready = all(v["ok"] for v in c.values())
        response.status_code = 200 if ready else 503
        return {"ready": ready, "checks": c}

    @app.get("/metrics")
    def metrics() -> Response:
        c = checks()
        d = c["directory"]
        gauges = {
            "ready": all(v["ok"] for v in c.values()),
            "schema_version": c["schema"]["version"],
            "db_bytes": settings.db_path.stat().st_size,
            "disk_free_bytes": c["storage"]["free_bytes"],
            "signing_keys_active": c["signing"]["active_keys"],
            "signing_keys_pending": c["signing"]["pending_keys"],
            "signing_keys_published": c["signing"]["published_keys"],
            "roomsd_servers": d["roomsd_servers"],
            "agentd_instances": d["agentd_instances"],
            "peers": d["peers"],
            "expired_leases": d["expired_leases"],
            "open_offers": d["open_offers"],
        }
        return Response(ops.prometheus("lobbyd", gauges), media_type="text/plain; version=0.0.4")

    app.include_router(identity.router)
    app.include_router(directory.router)
    app.include_router(peers.router)
    return app
