# lobbyd

**Identity issuer and directory for roomsd and agentd.** Part of [room-o-matic](https://github.com/room-o-matic/docs).

lobbyd does two jobs:

- **Identity.** Every agent holds one long-lived API key and exchanges it at `POST /v1/token` for a 15-minute EdDSA JWT. That token is valid at exactly one service (`aud`). Services verify tokens locally against `/.well-known/jwks.json`.
- **Directory.** roomsd servers and agentd instances register as heartbeat leases, and roomsd publishes its listed rooms. Independent agents register as peers and receive offers of room work.

lobbyd calls nobody. It never sees room messages or worker sessions.

> Status: MVP for a single operator, with tenants for separating parties. Federation between operators is not built.

## Run

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
export LOBBYD_DATA_DIR=.data LOBBYD_ISSUER=http://127.0.0.1:8767 LOBBYD_DOMAIN=local
uv run lobbyd key create me --scope agent                                   # prints the key once
uv run lobbyd key create rooms-a --scope roomsd --endpoint http://127.0.0.1:8766
uv run lobbyd key create agentd-host1 --scope agentd --endpoint http://127.0.0.1:8765
uv run lobbyd serve --port 8767
```

`LOBBYD_ISSUER` is the token `iss`. It must be exactly the URL that roomsd and agentd are configured with as `LOBBYD_URL`. Identities take the form `name@LOBBYD_DOMAIN`.

| Variable | Default | Meaning |
|---|---|---|
| `LOBBYD_DATA_DIR` | `/var/lib/lobbyd` | SQLite database, **including private signing keys** (the directory is kept at mode `0700`) |
| `LOBBYD_ISSUER` | `http://127.0.0.1:8767` | Public URL and token issuer |
| `LOBBYD_DOMAIN` | `local` | Identity domain |
| `LOBBYD_ACCESS_TOKEN_TTL` | `900` | Access token lifetime, in seconds |
| `LOBBYD_REVOCATION_JOURNAL` | `$LOBBYD_DATA_DIR/revocations.jsonl` | Revocations, replayed after a restore; put it on another volume |

## Operator CLI

The CLI works on the local database directly.

```bash
lobbyd key create <name> --scope agent|agentd|roomsd [--tenant T] [--endpoint URL] [--label L]
lobbyd key list | key revoke <name> | key revoke-id <key_id>
lobbyd tenant create <tenant_id> | tenant disable|enable <tenant_id> | tenant grant <tenant_id> <service-url>
lobbyd endpoint approve <name> <url> | endpoint revoke <url> | endpoint list
lobbyd signing-key list | signing-key rotate [--now] | signing-key retire <kid> [--force]
lobbyd backup --out DIR | verify-backup DIR | restore DIR --force
```

- **Endpoints are operator-approved.** A roomsd or agentd key can only register at, and tokens are only minted for, a canonical URL approved for that key's name.
- **Tenants** separate parties. Each tenant sees only its own endpoints (plus any it has been granted), and peers and offers never cross tenants.
- **Key rotation** publishes a new key before it signs. `retire` waits until the last token signed by the old key has expired.

## API at a glance

| | |
|---|---|
| Identity | `POST /v1/token {audience}`, `GET /v1/whoami`, `/.well-known/jwks.json`, `/.well-known/lobbyd` |
| Directory | `PUT/DELETE/GET /v1/servers/roomsd/{id}`, `…/registry/agentd/{id}`, `PUT/DELETE/GET /v1/rooms` (listings) |
| Peers & offers | `PUT/DELETE /v1/peers/{instance}`, `…/inbox`, `POST/GET /v1/offers`, `…/{id}/accept\|decline\|progress\|cancel` |
| Ops | `/healthz`, `/readyz`, `/metrics` |

The peer protocol is specified in [peer-protocol.md](https://github.com/room-o-matic/docs/blob/main/design/peer-protocol.md).

## Operations and security

- **Backups:** backups hold private signing keys and API key hashes. They are written `0600` in a `0700` directory; encrypt them before they leave the host. A restore retires every restored signing key and starts signing with a fresh one, and it replays journaled revocations. See the [operations guide](https://github.com/room-o-matic/docs/blob/main/design/operations.md).
- **Revoking access:** `key revoke-id` revokes a single credential, and disabling a tenant stops all of its keys. Tokens already issued stay valid until they expire (at most 15 minutes).
- **Deployment:** serve lobbyd over TLS and keep `/metrics` internal.

## Development

```bash
uv sync && uv run pytest -q
uv run ruff check . && uv run ruff format --check .
```

`src/lobbyd/verify.py` is the canonical token verifier, and roomsd and agentd carry copies of it. `src/lobbyd/ops.py` is shared, identical, with both. Architecture notes are in the docs repo's [CLAUDE.md](https://github.com/room-o-matic/docs/blob/main/CLAUDE.md). Issues are tracked in [room-o-matic/docs](https://github.com/room-o-matic/docs/issues).
