from fastapi import APIRouter, HTTPException, status

from lobbyd import db, endpoints, signing
from lobbyd.deps import Caller, Conn, SettingsDep
from lobbyd.models import TokenRequest, TokenResponse, WellKnown, WhoAmI
from lobbyd.urls import canonical_url

router = APIRouter(tags=["identity"])


@router.get("/.well-known/lobbyd")
def well_known(settings: SettingsDep) -> WellKnown:
    return WellKnown(
        issuer=settings.issuer,
        domain=settings.domain,
        jwks_uri=f"{settings.issuer}/.well-known/jwks.json",
        token_endpoint=f"{settings.issuer}/v1/token",
        access_token_ttl_seconds=settings.access_token_ttl_seconds,
    )


@router.get("/.well-known/jwks.json")
def jwks(conn: Conn) -> dict:
    return signing.jwks(conn)


@router.post("/v1/token")
def token(req: TokenRequest, conn: Conn, caller: Caller, settings: SettingsDep) -> TokenResponse:
    """Exchange an API key for an access token valid only at `audience`, which must be
    an operator-approved service endpoint: credentials are never minted for arbitrary
    destinations (docs#5)."""
    try:
        audience = canonical_url(req.audience)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"bad audience: {e}") from e
    if endpoints.lookup(conn, audience) is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"{audience} is not an approved service endpoint"
        )
    access_token, claims = signing.issue(
        conn,
        issuer=settings.issuer,
        subject=caller.identity,
        audience=audience,
        scope=caller.scope,
        ttl_seconds=settings.access_token_ttl_seconds,
    )
    with conn:
        db.audit(conn, caller.identity, "token.issue", audience=audience, jti=claims["jti"])
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.access_token_ttl_seconds,
        expires_at=claims["exp"],
        identity=caller.identity,
        scope=caller.scope,
        audience=audience,
    )


@router.get("/v1/whoami")
def whoami(caller: Caller) -> WhoAmI:
    return WhoAmI(name=caller.name, identity=caller.identity, scope=caller.scope)
