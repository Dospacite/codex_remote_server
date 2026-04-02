from __future__ import annotations

import argparse
import os
from urllib.parse import urlparse

from aiohttp import web

from .server import RelayConfig, create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Codex Remote relay server")
    parser.add_argument("--host", default=os.getenv("CODEX_REMOTE_RELAY_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CODEX_REMOTE_RELAY_PORT", "8787")))
    parser.add_argument(
        "--public-base-url",
        default=os.getenv("CODEX_REMOTE_RELAY_PUBLIC_BASE_URL", "https://relay.example.com"),
        help="Public HTTPS base URL advertised inside pairing codes.",
    )
    parser.add_argument(
        "--db-path",
        default=os.getenv("CODEX_REMOTE_RELAY_DB_PATH", "./relay.sqlite3"),
    )
    parser.add_argument(
        "--enroll-token",
        default=os.getenv("CODEX_REMOTE_RELAY_ENROLL_TOKEN"),
        help="Required by bridge enrollment requests when set.",
    )
    parser.add_argument(
        "--claim-ttl-seconds",
        type=int,
        default=int(os.getenv("CODEX_REMOTE_RELAY_CLAIM_TTL_SECONDS", "900")),
    )
    parser.add_argument(
        "--auth-max-skew-seconds",
        type=int,
        default=int(os.getenv("CODEX_REMOTE_RELAY_AUTH_MAX_SKEW_SECONDS", "60")),
    )
    parser.add_argument(
        "--ws-heartbeat-seconds",
        type=int,
        default=int(os.getenv("CODEX_REMOTE_RELAY_WS_HEARTBEAT_SECONDS", "20")),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    _validate_public_base_url(args.public_base_url)
    config = RelayConfig(
        host=args.host,
        port=args.port,
        public_base_url=args.public_base_url,
        db_path=args.db_path,
        enroll_token=args.enroll_token,
        claim_ttl_seconds=args.claim_ttl_seconds,
        auth_max_skew_seconds=args.auth_max_skew_seconds,
        ws_heartbeat_seconds=args.ws_heartbeat_seconds,
    )
    web.run_app(create_app(config), host=config.host, port=config.port)


def _validate_public_base_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return
    raise SystemExit("public-base-url must use HTTPS unless it targets localhost for development.")


if __name__ == "__main__":
    main()
