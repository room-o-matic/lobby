import json
from typing import Annotated, Literal

from pydantic import BaseModel, Field, JsonValue, field_validator

# A cheap shape check only; urls.canonical_url is the real gate (docs#5).
URL_PATTERN = r"^(?i:https?)://[^\s/]+(/[^\s]*)?$"
Label = Annotated[str, Field(min_length=1, max_length=64)]
MAX_METADATA_BYTES = 4096  # docs#11; see Settings.max_metadata_bytes


def _cap_metadata(value):
    if value is not None and len(json.dumps(value).encode()) > MAX_METADATA_BYTES:
        raise ValueError(f"metadata is over {MAX_METADATA_BYTES} bytes")
    return value


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
    tags: list[Label] = Field(default_factory=list, max_length=32)
    metadata: dict[str, JsonValue] | None = None
    ttl_seconds: int | None = Field(default=None, ge=5)

    @field_validator("metadata")
    @classmethod
    def _metadata_cap(cls, value):
        return _cap_metadata(value)


class RoomsdServer(BaseModel):
    server_id: str
    base_url: str
    registration_id: str
    listed_rooms: int = Field(
        description="listings held for this registration; roomsd republishes if it's short"
    )
    tags: list[str]
    metadata: dict[str, JsonValue] | None
    registered_at: str
    last_heartbeat_at: str
    expires_at: str


class AgentdRegistration(BaseModel):
    base_url: str = Field(pattern=URL_PATTERN, max_length=2048)
    worker_types: list[Label] = Field(min_length=1, max_length=64)
    profiles: list[Label] = Field(default_factory=list, max_length=64)
    max_sessions: int = Field(ge=0, le=10_000)
    active_sessions: int = Field(default=0, ge=0)
    metadata: dict[str, JsonValue] | None = None
    ttl_seconds: int | None = Field(default=None, ge=5)

    @field_validator("metadata")
    @classmethod
    def _metadata_cap(cls, value):
        return _cap_metadata(value)


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
    tags: list[Label] = Field(default_factory=list, max_length=32)


class ListedRoom(RoomListing):
    server_id: str
    updated_at: str


Availability = Literal["available", "busy", "draining"]
OfferState = Literal[
    "offered",
    "accepted",
    "declined",
    "expired",
    "cancelled",
    "joined",
    "working",
    "handed_off",
    "completed",
]


class PeerRegistration(BaseModel):
    owner: str | None = Field(default=None, max_length=200)
    capabilities: list[Label] = Field(default_factory=list, max_length=64)
    availability: Availability = "available"
    max_assignments: int = Field(default=1, ge=0, le=100)
    ttl_seconds: int | None = Field(default=None, ge=5)


class Peer(BaseModel):
    instance_id: str
    principal: str
    owner: str | None
    capabilities: list[str]
    availability: Availability
    max_assignments: int
    active_assignments: int
    registered_at: str
    last_heartbeat_at: str
    expires_at: str


class OfferCreate(BaseModel):
    offer_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9_.:-]{1,80}$",
        description="idempotency key; retrying with the same id returns the same offer",
    )
    to: str = Field(description="target principal, name@domain", max_length=200)
    room_url: str = Field(pattern=URL_PATTERN, max_length=2048)
    task: str = Field(min_length=1, max_length=16 * 1024)
    issue: str | None = Field(default=None, max_length=2048)
    role: str | None = Field(default=None, max_length=64)
    scope: list[Label] | None = Field(default=None, max_length=32)
    budget: dict[str, JsonValue] | None = None
    deadline_seconds: int | None = Field(
        default=None, ge=10, le=30 * 24 * 3600, description="respond-by, from now"
    )


class Offer(BaseModel):
    offer_id: str
    requester: str
    target: str
    room_url: str
    task: str
    issue: str | None
    role: str | None
    scope: list[str] | None
    budget: dict[str, JsonValue] | None
    deadline: str | None
    state: OfferState
    assigned_instance: str | None
    decline_reason: str | None
    created_at: str
    updated_at: str


class OfferTransition(BaseModel):
    instance_id: str = Field(max_length=80)
    reason: str | None = Field(default=None, max_length=1000)


class OfferProgress(OfferTransition):
    state: Literal["joined", "working", "handed_off", "completed"]


class TransitionResult(BaseModel):
    offer: Offer
    changed: bool = Field(description="false when this exact transition already happened")
