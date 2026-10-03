import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    # The URL other services use to reach lobbyd. Also the JWT `iss`, so it must be stable.
    issuer: str = "http://127.0.0.1:8767"
    # Identity domain: every identity this lobbyd issues is `name@domain`.
    domain: str = "local"
    access_token_ttl_seconds: int = 900
    # Key rotation (docs#6): a new key is published this long before it starts signing, so
    # verifiers' caches (TokenVerifier.cache_seconds, default 300) pick it up first; and a
    # key can be retired only once its last token has expired, plus clock skew.
    key_publish_lead_seconds: int = 360
    clock_skew_seconds: int = 60
    # docs#11 budgets: requests over them get 413/422/429.
    token_rate_per_minute: int = 120  # per API key
    audit_retention_days: int = 30
    max_metadata_bytes: int = 4096
    max_listed_rooms_per_server: int = 1000
    max_peer_instances: int = 16  # per agent
    max_open_offers: int = 200  # per requester
    default_lease_ttl_seconds: int = 60
    max_lease_ttl_seconds: int = 600

    @property
    def db_path(self) -> Path:
        return self.data_dir / "lobbyd.sqlite"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            data_dir=Path(os.environ.get("LOBBYD_DATA_DIR", "/var/lib/lobbyd")),
            issuer=os.environ.get("LOBBYD_ISSUER", cls.issuer).rstrip("/"),
            domain=os.environ.get("LOBBYD_DOMAIN", cls.domain),
            access_token_ttl_seconds=int(os.environ.get("LOBBYD_ACCESS_TOKEN_TTL", 900)),
        )
