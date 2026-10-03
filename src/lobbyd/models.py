from pydantic import BaseModel, Field, JsonValue

URL_PATTERN = r"^https?://[^\s/]+(/[^\s]*)?$"


class WellKnown(BaseModel):
    issuer: str
    domain: str
    jwks_uri: str
    token_endpoint: str
    access_token_ttl_seconds: int


class TokenRequest(BaseModel):
    audience: str = Field(
        pattern=URL_PATTERN, max_length=2048, description="base URL of the target service"
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    expires_at: int
    identity: str
    scope: str
    audience: str


class WhoAmI(BaseModel):
    name: str
    identity: str
    scope: str


class RoomsdRegistration(BaseModel):
    base_url: str = Field(pattern=URL_PATTERN, max_length=2048)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, JsonValue] | None = None
    ttl_seconds: int | None = Field(default=None, ge=5)


class RoomsdServer(BaseModel):
    server_id: str
    base_url: str
    tags: list[str]
    metadata: dict[str, JsonValue] | None
    registered_at: str
    last_heartbeat_at: str
    expires_at: str


class AgentdRegistration(BaseModel):
    base_url: str = Field(pattern=URL_PATTERN, max_length=2048)
    worker_types: list[str] = Field(min_length=1)
    profiles: list[str] = Field(default_factory=list)
    max_sessions: int = Field(ge=0)
    active_sessions: int = Field(default=0, ge=0)
    metadata: dict[str, JsonValue] | None = None
    ttl_seconds: int | None = Field(default=None, ge=5)


class AgentdInstance(BaseModel):
    instance_id: str
    base_url: str
    worker_types: list[str]
    profiles: list[str]
    max_sessions: int
    active_sessions: int
    available_sessions: int
    metadata: dict[str, JsonValue] | None
    registered_at: str
    last_heartbeat_at: str
    expires_at: str


class RoomListing(BaseModel):
    room_url: str = Field(pattern=URL_PATTERN, max_length=2048)
    name: str = Field(min_length=1, max_length=200)
    purpose: str | None = Field(default=None, max_length=4000)
    tags: list[str] = Field(default_factory=list)


class ListedRoom(RoomListing):
    server_id: str
    updated_at: str
