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

## Public VPS deployment

The repository includes a production-oriented Docker Compose stack:

- `compose.yaml`
- `compose.nginx.yaml`
- `deploy/Caddyfile`
- `.env.example`

Recommended topology:

- `caddy` terminates TLS on `:80` and `:443`
- `relay` listens only on the internal Docker network
- SQLite lives on a persistent Docker volume
- the public relay URL is `https://your-domain`

Alternative topology:

- host `nginx` terminates TLS on the VPS
- `docker compose -f compose.nginx.yaml up -d --build` publishes the relay only on `127.0.0.1:8787`
- host `nginx` proxies `cr.rousoftware.com` or another relay domain to `http://127.0.0.1:8787`

### VPS checklist

1. Point a DNS `A` record at your VPS for the relay domain.
2. Open inbound `80/tcp` and `443/tcp` on the VPS firewall.
3. Install Docker Engine and the Docker Compose plugin.
4. Clone this repository onto the VPS.
5. Copy `.env.example` to `.env` and fill in real values.
6. Start the stack with `docker compose up -d --build`.

If you already run `nginx` on the host and do not want a Caddy container, use:

```bash
cp .env.example .env
docker compose -f compose.nginx.yaml up -d --build
docker compose -f compose.nginx.yaml logs -f
```

### Example deployment

```bash
cp .env.example .env
docker compose up -d --build
docker compose logs -f
```

Required `.env` values:

- `CODEX_REMOTE_DOMAIN`: public DNS name for the relay, for example `relay.example.com`
- `CODEX_REMOTE_ACME_EMAIL`: email address used for Let's Encrypt
- `CODEX_REMOTE_RELAY_ENROLL_TOKEN`: long random bootstrap secret for bridge enrollment

Adjustable capacity control:

- `CODEX_REMOTE_RELAY_MAX_CONCURRENT_CLIENTS`: maximum number of concurrently authenticated mobile client connections, default `16384`

The resulting public relay URL is:

```text
https://$CODEX_REMOTE_DOMAIN
```

Use that exact URL in bridge configuration. It is also the URL embedded into pairing codes.

### Health checks

- application endpoint: `GET /healthz`
- container health check: built into the relay Docker image

### Persistence

The compose stack uses named volumes for:

- relay SQLite data
- Caddy certificates and config

Do not keep the SQLite database only inside the container filesystem if you want the relay to survive container recreation.

## Local Python install

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
- `--max-concurrent-clients`: maximum number of concurrently authenticated mobile client connections, default `16384`

Environment variables:

- `CODEX_REMOTE_RELAY_HOST`
- `CODEX_REMOTE_RELAY_PORT`
- `CODEX_REMOTE_RELAY_PUBLIC_BASE_URL`
- `CODEX_REMOTE_RELAY_DB_PATH`
- `CODEX_REMOTE_RELAY_ENROLL_TOKEN`
- `CODEX_REMOTE_RELAY_CLAIM_TTL_SECONDS`
- `CODEX_REMOTE_RELAY_AUTH_MAX_SKEW_SECONDS`
- `CODEX_REMOTE_RELAY_WS_HEARTBEAT_SECONDS`
- `CODEX_REMOTE_RELAY_MAX_CONCURRENT_CLIENTS`

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
- keep the relay host patched; this service is internet-facing

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
