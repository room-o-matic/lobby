import json
import os
import sqlite3
from pathlib import Path

from lobbyd.ids import now_iso

SCHEMA = """
-- docs#11: every key belongs to a tenant (an owner). The built-in "internal" tenant is the
-- operator's own and can host services; other tenants can't unless granted can_host.
create table if not exists tenants (
  tenant_id text primary key,
  name text,
  can_host integer not null default 0,
  status text not null default 'active',
  created_at text not null
);

create table if not exists api_keys (
  key_hash text primary key,
  key_id text not null unique,
  name text not null,
  scope text not null,
  tenant_id text not null references tenants(tenant_id),
  label text,
  created_at text not null,
  revoked_at text
);

create index if not exists api_keys_name on api_keys(name);

create table if not exists signing_keys (
  kid text primary key,
  private_pem text not null,
  created_at text not null,
  -- Published in the JWKS from created_at, but only signs from activates_at (docs#6).
  activates_at text not null,
  last_issued_at text,
  retired_at text
);

create table if not exists endpoints (
  url text primary key,
  name text not null,
  scope text not null,
  tenant_id text not null,
  max_sessions integer not null,
  worker_types_json text,
  approved_at text not null
);

create index if not exists endpoints_name on endpoints(name);

-- docs#11: lets a tenant use (see, and get tokens for) another tenant's service endpoint.
create table if not exists service_grants (
  tenant_id text not null,
  url text not null,
  granted_at text not null,
  primary key (tenant_id, url)
);

create table if not exists roomsd_servers (
  server_id text primary key,
  base_url text not null,
  -- docs#19: identifies one registration. Kept across heartbeats and lapses on the same
  -- endpoint; replaced on endpoint migration or after an explicit DELETE.
  registration_id text not null,
  tags_json text not null,
  metadata_json text,
  registered_at text not null,
  last_heartbeat_at text not null,
  expires_at text not null
);

create table if not exists agentd_instances (
  instance_id text primary key,
  base_url text not null,
  worker_types_json text not null,
  profiles_json text not null,
  max_sessions integer not null,
  active_sessions integer not null,
  metadata_json text,
  registered_at text not null,
  last_heartbeat_at text not null,
  expires_at text not null
);

create table if not exists listed_rooms (
  room_url text primary key,
  server_id text not null,
  registration_id text not null,
  name text not null,
  purpose text,
  tags_json text not null,
  updated_at text not null
);

create index if not exists listed_rooms_server on listed_rooms(server_id);

-- Independent named agents (docs#7): one row per running session of a principal.
create table if not exists peers (
  instance_id text primary key,
  principal text not null,
  tenant_id text not null,
  owner text,
  capabilities_json text not null,
  availability text not null,
  max_assignments integer not null,
  registered_at text not null,
  last_heartbeat_at text not null,
  expires_at text not null
);

create index if not exists peers_principal on peers(principal);

create table if not exists offers (
  offer_id text primary key,
  requester text not null,
  target text not null,
  room_url text not null,
  task text not null,
  issue text,
  role text,
  scope_json text,
  budget_json text,
  deadline text,
  state text not null,
  assigned_instance text,
  decline_reason text,
  created_at text not null,
  updated_at text not null,
  delivered_at text
);

create index if not exists offers_target_state on offers(target, state);
create index if not exists offers_requester on offers(requester, created_at);

create table if not exists audit (
  id integer primary key autoincrement,
  actor text not null,
  action text not null,
  detail_json text,
  created_at text not null
);
"""


def connect(path: Path) -> sqlite3.Connection:
    # One connection per request, but FastAPI runs a sync dependency and its route in
    # different threadpool threads, so the connection must be allowed to change threads.
    # It is never used by two threads at once.
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("pragma busy_timeout = 10000")
    return conn


INTERNAL_TENANT = "internal"


def init_db(path: Path) -> None:
    # The DB holds private signing keys: keep the data dir private to this user.
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    conn = connect(path)
    try:
        conn.execute("pragma journal_mode = wal")
        conn.executescript(SCHEMA)
        with conn:
            conn.execute(
                "insert or ignore into tenants (tenant_id, name, can_host, created_at)"
                " values (?, 'operator', 1, ?)",
                (INTERNAL_TENANT, now_iso()),
            )
    finally:
        conn.close()


def audit(conn: sqlite3.Connection, actor: str, action: str, **detail) -> None:
    detail = {k: v for k, v in detail.items() if v is not None}
    conn.execute(
        "insert into audit (actor, action, detail_json, created_at) values (?, ?, ?, ?)",
        (actor, action, json.dumps(detail) if detail else None, now_iso()),
    )
