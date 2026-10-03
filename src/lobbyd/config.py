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
