from fastapi import FastAPI

from lobbyd import db, signing
from lobbyd.config import Settings
from lobbyd.limits import AuditPruner, RateLimiter
from lobbyd.routes import directory, identity, peers


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    db.init_db(settings.db_path)
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

    app.include_router(identity.router)
    app.include_router(directory.router)
    app.include_router(peers.router)
    return app
