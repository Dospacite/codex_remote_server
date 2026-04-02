from __future__ import annotations

import asyncio
import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from aiohttp import WSMsgType, web

from .security import (
    PairingCodePayload,
    auth_payload,
    is_valid_public_signing_key,
    pairing_refresh_payload,
    random_token,
    session_bundle_payload,
    utc_now,
    verify_signature,
)
from .store import DeviceRecord, DeviceStore


@dataclass(slots=True)
class RelayConfig:
    host: str
    port: int
    public_base_url: str
    db_path: str
    enroll_token: str | None
    claim_ttl_seconds: int
    auth_max_skew_seconds: int
    ws_heartbeat_seconds: int
    max_concurrent_clients: int


@dataclass(slots=True)
class AuthenticatedPeer:
    device_id: str
    role: str
    ws: web.WebSocketResponse
    device: DeviceRecord
    session_bundle: dict[str, Any]


@dataclass(slots=True)
class RelaySession:
    session_id: str
    bridge: AuthenticatedPeer
    client: AuthenticatedPeer


@dataclass(slots=True)
class PendingBridgeDownload:
    request_id: str
    device_id: str
    queue: asyncio.Queue[dict[str, Any]]


class RelayRuntime:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._peers: dict[str, dict[str, AuthenticatedPeer]] = {}
        self._sessions: dict[str, RelaySession] = {}
        self._pending_bridge_downloads: dict[str, PendingBridgeDownload] = {}

    async def register(
        self,
        peer: AuthenticatedPeer,
        *,
        max_concurrent_clients: int,
    ) -> RelaySession | None:
        async with self._lock:
            device_peers = self._peers.setdefault(peer.device_id, {})
            previous = device_peers.get(peer.role)
            if (
                peer.role == "client"
                and previous is None
                and self._client_connection_count_locked() >= max_concurrent_clients
            ):
                raise web.HTTPTooManyRequests(text="Concurrent client limit reached.")
            if previous is not None and previous.ws is not peer.ws:
                await previous.ws.close(message=b"Superseded by newer connection.")
            device_peers[peer.role] = peer
            self._sessions.pop(peer.device_id, None)
            counterpart_role = "client" if peer.role == "bridge" else "bridge"
            counterpart = device_peers.get(counterpart_role)
            if counterpart is None:
                return None
            session = RelaySession(
                session_id=random_token(18),
                bridge=peer if peer.role == "bridge" else counterpart,
                client=peer if peer.role == "client" else counterpart,
            )
            self._sessions[peer.device_id] = session
            return session

    def _client_connection_count_locked(self) -> int:
        return sum(1 for peers in self._peers.values() if "client" in peers)

    async def unregister(self, device_id: str, role: str, ws: web.WebSocketResponse) -> None:
        counterpart_ws: web.WebSocketResponse | None = None
        session_id: str | None = None
        pending_downloads: list[PendingBridgeDownload] = []
        async with self._lock:
            device_peers = self._peers.get(device_id)
            if device_peers is None:
                return
            current = device_peers.get(role)
            if current is not None and current.ws is ws:
                device_peers.pop(role, None)
                counterpart_role = "client" if role == "bridge" else "bridge"
                counterpart = device_peers.get(counterpart_role)
                if counterpart is not None:
                    counterpart_ws = counterpart.ws
                previous_session = self._sessions.pop(device_id, None)
                if previous_session is not None:
                    session_id = previous_session.session_id
                if role == "bridge":
                    stale_request_ids = [
                        request_id
                        for request_id, download in self._pending_bridge_downloads.items()
                        if download.device_id == device_id
                    ]
                    for request_id in stale_request_ids:
                        pending_downloads.append(
                            self._pending_bridge_downloads.pop(request_id)
                        )
            if not device_peers:
                self._peers.pop(device_id, None)
        if counterpart_ws is not None and not counterpart_ws.closed:
            await counterpart_ws.send_json(
                {
                    "deviceId": device_id,
                    "reason": "peer_disconnected",
                    "sessionId": session_id,
                    "type": "close_session",
                }
            )
        for download in pending_downloads:
            await download.queue.put(
                {
                    "type": "bridge_download_error",
                    "requestId": download.request_id,
                    "message": "Bridge disconnected.",
                }
            )

    async def forward(
        self,
        *,
        device_id: str,
        sender_role: str,
        session_id: str,
        message: str,
    ) -> None:
        async with self._lock:
            device_peers = self._peers.get(device_id)
            session = self._sessions.get(device_id)
            if device_peers is None or session is None:
                raise web.HTTPConflict(text="No active counterpart.")
            if session.session_id != session_id:
                raise web.HTTPConflict(text="Session is no longer active.")
            recipient_role = "client" if sender_role == "bridge" else "bridge"
            recipient = device_peers.get(recipient_role)
            if recipient is None:
                raise web.HTTPConflict(text="No active counterpart.")
        await recipient.ws.send_str(message)

    async def start_bridge_download(
        self,
        *,
        device_id: str,
        token: str,
    ) -> PendingBridgeDownload:
        async with self._lock:
            bridge = self._peers.get(device_id, {}).get("bridge")
            if bridge is None:
                raise web.HTTPConflict(text="Bridge is not connected.")
            request_id = random_token(18)
            pending = PendingBridgeDownload(
                request_id=request_id,
                device_id=device_id,
                queue=asyncio.Queue(),
            )
            self._pending_bridge_downloads[request_id] = pending
        await bridge.ws.send_json(
            {
                "type": "bridge_download_request",
                "requestId": request_id,
                "token": token,
            }
        )
        return pending

    async def finish_bridge_download(self, request_id: str) -> None:
        async with self._lock:
            self._pending_bridge_downloads.pop(request_id, None)

    async def cancel_bridge_download(self, request_id: str) -> None:
        async with self._lock:
            pending = self._pending_bridge_downloads.get(request_id)
            if pending is None:
                return
            bridge = self._peers.get(pending.device_id, {}).get("bridge")
        if bridge is None or bridge.ws.closed:
            return
        await bridge.ws.send_json(
            {
                "type": "bridge_download_cancel",
                "requestId": request_id,
            }
        )

    async def handle_bridge_download_message(
        self,
        *,
        peer: AuthenticatedPeer,
        payload: dict[str, Any],
    ) -> None:
        request_id = _read_json_body(payload, "requestId")
        async with self._lock:
            pending = self._pending_bridge_downloads.get(request_id)
        if pending is None or peer.role != "bridge" or pending.device_id != peer.device_id:
            raise web.HTTPBadRequest(text="Unknown bridge download request.")
        await pending.queue.put(payload)
        if payload.get("type") in {"bridge_download_complete", "bridge_download_error"}:
            await self.finish_bridge_download(request_id)


def create_app(config: RelayConfig) -> web.Application:
    app = web.Application()
    app["config"] = config
    app["store"] = DeviceStore(config.db_path)
    app["runtime"] = RelayRuntime()
    app.router.add_get("/healthz", healthz)
    app.router.add_post("/api/v1/bridge/enroll", enroll_bridge)
    app.router.add_post("/api/v1/bridge/pairing-code", refresh_bridge_pairing_code)
    app.router.add_post("/api/v1/device/claim", claim_device)
    app.router.add_get("/api/v1/bridge-download/{device_id}/{token}", bridge_download)
    app.router.add_get("/ws", relay_ws)
    return app


async def healthz(_: web.Request) -> web.Response:
    return web.json_response({"ok": True})


def _read_json_body(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise web.HTTPBadRequest(text=f"Missing `{key}`.")
    return value


async def enroll_bridge(request: web.Request) -> web.Response:
    config: RelayConfig = request.app["config"]
    if config.enroll_token:
        provided = request.headers.get("X-Relay-Enroll-Token", "").strip()
        if not secrets.compare_digest(provided, config.enroll_token):
            raise web.HTTPUnauthorized(text="Invalid enrollment token.")
    payload = await request.json()
    bridge_label = _read_json_body(payload, "bridgeLabel")
    bridge_signing_public_key = _read_json_body(payload, "bridgeSigningPublicKey")
    if not is_valid_public_signing_key(bridge_signing_public_key):
        raise web.HTTPBadRequest(text="Invalid bridge signing public key.")
    store: DeviceStore = request.app["store"]
    record, claim_token = store.enroll_device(
        bridge_label=bridge_label,
        bridge_signing_public_key=bridge_signing_public_key,
        claim_ttl_seconds=config.claim_ttl_seconds,
    )
    pairing_code = PairingCodePayload(
        device_id=record.device_id,
        relay_url=config.public_base_url.rstrip("/"),
        claim_token=claim_token,
        bridge_signing_public_key=record.bridge_signing_public_key,
        bridge_label=record.bridge_label,
        expires_at=record.claim_expires_at or utc_now(),
    ).encode()
    return web.json_response(
        {
            "bridgeFingerprint": record.bridge_fingerprint,
            "bridgeLabel": record.bridge_label,
            "deviceId": record.device_id,
            "pairingCode": pairing_code,
            "pairingExpiresAt": record.claim_expires_at,
        }
    )


async def claim_device(request: web.Request) -> web.Response:
    payload = await request.json()
    try:
        pairing = PairingCodePayload.decode(_read_json_body(payload, "pairingCode"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    client_signing_public_key = _read_json_body(payload, "clientSigningPublicKey")
    if not is_valid_public_signing_key(client_signing_public_key):
        raise web.HTTPBadRequest(text="Invalid client signing public key.")
    client_label = str(payload.get("clientLabel", "Codex Remote")).strip() or "Codex Remote"
    if pairing.expires_at < utc_now():
        raise web.HTTPBadRequest(text="The pairing code has expired.")
    store: DeviceStore = request.app["store"]
    record = store.get_device(pairing.device_id)
    if record is None:
        raise web.HTTPNotFound(text="Unknown device.")
    if record.bridge_signing_public_key != pairing.bridge_signing_public_key:
        raise web.HTTPConflict(text="Bridge identity mismatch.")
    try:
        claimed = store.claim_device(
            device_id=pairing.device_id,
            claim_token=pairing.claim_token,
            client_signing_public_key=client_signing_public_key,
            client_label=client_label,
        )
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    return web.json_response(
        {
            "bridgeFingerprint": claimed.bridge_fingerprint,
            "bridgeLabel": claimed.bridge_label,
            "bridgeSigningPublicKey": claimed.bridge_signing_public_key,
            "clientLabel": claimed.client_label,
            "deviceId": claimed.device_id,
        }
    )


async def refresh_bridge_pairing_code(request: web.Request) -> web.Response:
    config: RelayConfig = request.app["config"]
    payload = await request.json()
    device_id = _read_json_body(payload, "deviceId")
    bridge_label = _read_json_body(payload, "bridgeLabel")
    bridge_signing_public_key = _read_json_body(payload, "bridgeSigningPublicKey")
    request_nonce = _read_json_body(payload, "requestNonce")
    request_signature = _read_json_body(payload, "requestSignature")
    request_timestamp = int(payload.get("requestTimestamp", 0))
    if abs(utc_now() - request_timestamp) > config.auth_max_skew_seconds:
        raise web.HTTPUnauthorized(text="Refresh timestamp is too old.")
    if not is_valid_public_signing_key(bridge_signing_public_key):
        raise web.HTTPBadRequest(text="Invalid bridge signing public key.")

    store: DeviceStore = request.app["store"]
    record = store.get_device(device_id)
    if record is None:
        raise web.HTTPNotFound(text="Unknown device.")
    if record.bridge_signing_public_key != bridge_signing_public_key:
        raise web.HTTPConflict(text="Bridge identity mismatch.")
    if not verify_signature(
        bridge_signing_public_key,
        request_signature,
        pairing_refresh_payload(
            device_id=device_id,
            bridge_label=bridge_label,
            bridge_signing_public_key=bridge_signing_public_key,
            request_nonce=request_nonce,
            request_timestamp=request_timestamp,
        ),
    ):
        raise web.HTTPUnauthorized(text="Refresh signature rejected.")

    try:
        refreshed, claim_token = store.refresh_pairing_code(
            device_id=device_id,
            claim_ttl_seconds=config.claim_ttl_seconds,
        )
    except ValueError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    pairing_code = PairingCodePayload(
        device_id=refreshed.device_id,
        relay_url=config.public_base_url.rstrip("/"),
        claim_token=claim_token,
        bridge_signing_public_key=refreshed.bridge_signing_public_key,
        bridge_label=refreshed.bridge_label,
        expires_at=refreshed.claim_expires_at or utc_now(),
    ).encode()
    return web.json_response(
        {
            "bridgeFingerprint": refreshed.bridge_fingerprint,
            "bridgeLabel": refreshed.bridge_label,
            "deviceId": refreshed.device_id,
            "pairingCode": pairing_code,
            "pairingExpiresAt": refreshed.claim_expires_at,
        }
    )


async def bridge_download(request: web.Request) -> web.StreamResponse:
    device_id = request.match_info["device_id"].strip()
    token = request.match_info["token"].strip()
    runtime: RelayRuntime = request.app["runtime"]
    pending = await runtime.start_bridge_download(device_id=device_id, token=token)
    response: web.StreamResponse | None = None
    try:
        first = await asyncio.wait_for(pending.queue.get(), timeout=15)
        if first.get("type") == "bridge_download_error":
            raise web.HTTPNotFound(text=str(first.get("message", "Download unavailable.")))
        if first.get("type") != "bridge_download_ready":
            raise web.HTTPBadGateway(text="Bridge did not start download correctly.")

        file_name = str(first.get("fileName") or "download.bin")
        content_type = str(first.get("contentType") or "application/octet-stream")
        size_bytes = int(first.get("sizeBytes") or 0)
        headers = {
            "Content-Disposition": f'attachment; filename="{file_name}"',
            "Content-Type": content_type,
        }
        if size_bytes > 0:
            headers["Content-Length"] = str(size_bytes)
        response = web.StreamResponse(status=200, headers=headers)
        await response.prepare(request)

        while True:
            event = await pending.queue.get()
            event_type = event.get("type")
            if event_type == "bridge_download_chunk":
                data = base64.b64decode(str(event.get("dataBase64") or ""))
                await response.write(data)
                continue
            if event_type == "bridge_download_complete":
                break
            if event_type == "bridge_download_error":
                raise web.HTTPBadGateway(
                    text=str(event.get("message", "Bridge download failed."))
                )
            raise web.HTTPBadGateway(text="Unexpected bridge download event.")
        await response.write_eof()
        return response
    except (asyncio.CancelledError, ConnectionResetError):
        await runtime.cancel_bridge_download(pending.request_id)
        raise
    finally:
        await runtime.finish_bridge_download(pending.request_id)


async def relay_ws(request: web.Request) -> web.StreamResponse:
    config: RelayConfig = request.app["config"]
    ws = web.WebSocketResponse(heartbeat=config.ws_heartbeat_seconds)
    await ws.prepare(request)
    connection_id = random_token(12)
    challenge = random_token(24)
    device_id: str | None = None
    role: str | None = None
    await ws.send_json(
        {
            "challenge": challenge,
            "connectionId": connection_id,
            "issuedAt": utc_now(),
            "type": "challenge",
        }
    )
    try:
        first = await ws.receive()
        if first.type != WSMsgType.TEXT:
            raise web.HTTPUnauthorized(text="Expected authenticate message.")
        payload = json.loads(first.data)
        if payload.get("type") != "authenticate":
            raise web.HTTPUnauthorized(text="Expected authenticate message.")
        device_id = _read_json_body(payload, "deviceId")
        role = _read_json_body(payload, "role")
        if role not in {"bridge", "client"}:
            raise web.HTTPUnauthorized(text="Invalid role.")
        auth_nonce = _read_json_body(payload, "authNonce")
        auth_signature = _read_json_body(payload, "authSignature")
        auth_timestamp = int(payload.get("authTimestamp", 0))
        if abs(utc_now() - auth_timestamp) > config.auth_max_skew_seconds:
            raise web.HTTPUnauthorized(text="Authentication timestamp is too old.")
        session_bundle = payload.get("sessionBundle")
        if not isinstance(session_bundle, dict):
            raise web.HTTPUnauthorized(text="Missing session bundle.")
        session_public_key = _read_json_body(session_bundle, "sessionPublicKey")
        session_nonce = _read_json_body(session_bundle, "sessionNonce")
        session_signature = _read_json_body(session_bundle, "signature")
        session_signed_at = int(session_bundle.get("signedAt", 0))
        store: DeviceStore = request.app["store"]
        device = store.get_device(device_id)
        if device is None:
            raise web.HTTPUnauthorized(text="Unknown device.")
        public_key = (
            device.bridge_signing_public_key
            if role == "bridge"
            else device.client_signing_public_key
        )
        if not public_key:
            raise web.HTTPUnauthorized(text="This device is not paired yet.")
        if not verify_signature(
            public_key,
            auth_signature,
            auth_payload(
                challenge=challenge,
                connection_id=connection_id,
                device_id=device_id,
                role=role,
                auth_nonce=auth_nonce,
                auth_timestamp=auth_timestamp,
            ),
        ):
            raise web.HTTPUnauthorized(text="Authentication signature rejected.")
        if not verify_signature(
            public_key,
            session_signature,
            session_bundle_payload(
                device_id=device_id,
                role=role,
                session_public_key=session_public_key,
                session_nonce=session_nonce,
                signed_at=session_signed_at,
            ),
        ):
            raise web.HTTPUnauthorized(text="Session bundle signature rejected.")
        runtime: RelayRuntime = request.app["runtime"]
        peer = AuthenticatedPeer(
            device_id=device_id,
            role=role,
            ws=ws,
            device=device,
            session_bundle={
                "sessionNonce": session_nonce,
                "sessionPublicKey": session_public_key,
                "signature": session_signature,
                "signedAt": session_signed_at,
            },
        )
        session = await runtime.register(
            peer,
            max_concurrent_clients=config.max_concurrent_clients,
        )
        await ws.send_json(
            {
                "deviceId": device_id,
                "role": role,
                "status": "authenticated",
                "type": "authenticated",
            }
        )
        if session is not None:
            await _announce_session(
                session=session,
                device_id=device_id,
            )
        async for message in ws:
            if message.type == WSMsgType.TEXT:
                await _handle_authenticated_message(request, peer, json.loads(message.data))
            elif message.type == WSMsgType.ERROR:
                break
    finally:
        if device_id and role:
            runtime = request.app["runtime"]
            await runtime.unregister(device_id, role, ws)
    return ws


async def _announce_session(
    *,
    session: RelaySession,
    device_id: str,
) -> None:
    await session.bridge.ws.send_json(
        {
            "deviceId": device_id,
            "peerRole": "client",
            "peerSessionBundle": session.client.session_bundle,
            "peerSigningPublicKey": session.client.device.client_signing_public_key,
            "sessionId": session.session_id,
            "type": "session_open",
        }
    )
    await session.client.ws.send_json(
        {
            "deviceId": device_id,
            "peerRole": "bridge",
            "peerSessionBundle": session.bridge.session_bundle,
            "peerSigningPublicKey": session.bridge.device.bridge_signing_public_key,
            "sessionId": session.session_id,
            "type": "session_open",
        }
    )


async def _handle_authenticated_message(
    request: web.Request,
    peer: AuthenticatedPeer,
    payload: dict[str, Any],
) -> None:
    message_type = payload.get("type")
    if message_type in {
        "bridge_download_ready",
        "bridge_download_chunk",
        "bridge_download_complete",
        "bridge_download_error",
    }:
        runtime: RelayRuntime = request.app["runtime"]
        await runtime.handle_bridge_download_message(peer=peer, payload=payload)
        return
    session_id = _read_json_body(payload, "sessionId")
    if message_type == "relay_frame":
        runtime: RelayRuntime = request.app["runtime"]
        await runtime.forward(
            device_id=peer.device_id,
            sender_role=peer.role,
            session_id=session_id,
            message=json.dumps(payload, separators=(",", ":"), sort_keys=True),
        )
        return
    if message_type == "close_session":
        runtime = request.app["runtime"]
        await runtime.forward(
            device_id=peer.device_id,
            sender_role=peer.role,
            session_id=session_id,
            message=json.dumps(payload, separators=(",", ":"), sort_keys=True),
        )
        return
    raise web.HTTPBadRequest(text="Unsupported message type.")
