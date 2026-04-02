# codex_remote_server

`codex_remote_server` is the authenticated relay service for Codex Remote.

It is intentionally small: it handles bridge enrollment, device claiming, authenticated WebSocket session setup, and relay-backed HTTP downloads. The relay forwards encrypted Codex traffic, but it is not trusted with plaintext session content.

## What it does

- enrolls bridge identities
- issues one-time pairing codes for mobile devices
- authenticates bridge and client WebSocket connections
- opens relay sessions between a claimed device and a bridge
- forwards encrypted relay frames
- proxies secure, temporary HTTP downloads from the bridge

## Requirements

- Python 3.12+
- HTTPS in production
- persistent storage for the relay SQLite database

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Run locally

```bash
codex-remote-server \
  --host 0.0.0.0 \
  --port 8787 \
  --public-base-url https://relay.example.com \
  --db-path ./relay.sqlite3 \
  --enroll-token your-bootstrap-token
```

For localhost-only development, `--public-base-url` may use `http://localhost:8787`. In production it must be HTTPS.

## CLI flags

- `--host`: bind address, default `0.0.0.0`
- `--port`: listen port, default `8787`
- `--public-base-url`: public base URL embedded in pairing codes
- `--db-path`: SQLite database path, default `./relay.sqlite3`
- `--enroll-token`: optional bootstrap token required for bridge enrollment
- `--claim-ttl-seconds`: pairing code lifetime, default `900`
- `--auth-max-skew-seconds`: allowed auth clock skew, default `60`
- `--ws-heartbeat-seconds`: relay WebSocket heartbeat interval, default `20`

Environment variables:

- `CODEX_REMOTE_RELAY_HOST`
- `CODEX_REMOTE_RELAY_PORT`
- `CODEX_REMOTE_RELAY_PUBLIC_BASE_URL`
- `CODEX_REMOTE_RELAY_DB_PATH`
- `CODEX_REMOTE_RELAY_ENROLL_TOKEN`
- `CODEX_REMOTE_RELAY_CLAIM_TTL_SECONDS`
- `CODEX_REMOTE_RELAY_AUTH_MAX_SKEW_SECONDS`
- `CODEX_REMOTE_RELAY_WS_HEARTBEAT_SECONDS`

## HTTP and WebSocket surface

- `GET /healthz`
- `POST /api/v1/bridge/enroll`
- `POST /api/v1/device/claim`
- `GET /api/v1/bridge-download/{device_id}/{token}`
- `GET /ws`

## Security model

- bridge and mobile identities use Ed25519 signatures
- each live session derives an ephemeral shared key with X25519
- relay frames are encrypted end to end with ChaCha20-Poly1305
- the relay stores public identity material and hashed pairing artifacts, not plaintext session traffic
- bridge enrollment can be protected with `--enroll-token`
- relay download URLs are short-lived and bridge-scoped

## Production notes

- terminate TLS in front of the relay or on the relay itself
- set a non-empty enrollment token unless you intentionally want open bridge enrollment
- persist the SQLite database on durable storage
- use a stable `--public-base-url`; this value is embedded in pairing codes and QR payloads
- expose only the public relay URL, not the bridge workstation or local `app-server`

## Docker

Build:

```bash
docker build -t codex-remote-relay .
```

Run:

```bash
docker run --rm \
  -p 8787:8787 \
  -e CODEX_REMOTE_RELAY_ENROLL_TOKEN=your-bootstrap-token \
  codex-remote-relay \
  --public-base-url https://relay.example.com
```

Persist the database:

```bash
docker run --rm \
  -p 8787:8787 \
  -v codex-remote-relay-data:/data \
  -e CODEX_REMOTE_RELAY_ENROLL_TOKEN=your-bootstrap-token \
  codex-remote-relay \
  --db-path /data/relay.sqlite3 \
  --public-base-url https://relay.example.com
```

## Development

Run tests:

```bash
python -m unittest discover -s tests
```

Run the package directly from source:

```bash
python -m codex_remote_server --help
```

## Repository

- GitHub: https://github.com/Dospacite/codex_remote_server
- Issues: https://github.com/Dospacite/codex_remote_server/issues

## License

GPL-3.0-only. See `LICENSE`.
