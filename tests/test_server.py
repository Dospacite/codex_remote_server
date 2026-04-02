from __future__ import annotations

import unittest

from aiohttp import web

from codex_remote_server.server import AuthenticatedPeer, RelayRuntime
from codex_remote_server.store import DeviceRecord


class _FakeWebSocket:
    def __init__(self) -> None:
        self.closed = False
        self.json_messages: list[dict[str, object]] = []
        self.text_messages: list[str] = []
        self.close_calls = 0

    async def close(self, message: bytes | None = None) -> None:
        self.closed = True
        self.close_calls += 1

    async def send_json(self, payload: dict[str, object]) -> None:
        self.json_messages.append(payload)

    async def send_str(self, payload: str) -> None:
        self.text_messages.append(payload)


class RelayRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.device = DeviceRecord(
            device_id="device",
            bridge_label="bridge",
            bridge_signing_public_key="bridge-key",
            bridge_fingerprint="fingerprint",
            client_signing_public_key="client-key",
            client_label="client",
            claim_token_hash=None,
            claim_token_salt=None,
            claim_expires_at=None,
            claimed_at=1,
        )

    async def test_forward_requires_current_session_id(self) -> None:
        runtime = RelayRuntime()
        bridge_ws = _FakeWebSocket()
        client_ws = _FakeWebSocket()
        bridge = AuthenticatedPeer(
            device_id="device",
            role="bridge",
            ws=bridge_ws,
            device=self.device,
            session_bundle={"sessionPublicKey": "a", "sessionNonce": "b", "signature": "c", "signedAt": 1},
        )
        client = AuthenticatedPeer(
            device_id="device",
            role="client",
            ws=client_ws,
            device=self.device,
            session_bundle={"sessionPublicKey": "d", "sessionNonce": "e", "signature": "f", "signedAt": 1},
        )
        self.assertIsNone(await runtime.register(bridge))
        session = await runtime.register(client)
        assert session is not None

        await runtime.forward(
            device_id="device",
            sender_role="client",
            session_id=session.session_id,
            message='{"ok":true}',
        )
        self.assertEqual(client_ws.text_messages, [])
        self.assertEqual(bridge_ws.text_messages, ['{"ok":true}'])

        with self.assertRaises(web.HTTPConflict):
            await runtime.forward(
                device_id="device",
                sender_role="client",
                session_id="stale-session",
                message='{"ok":false}',
            )

    async def test_unregister_notifies_counterpart(self) -> None:
        runtime = RelayRuntime()
        bridge_ws = _FakeWebSocket()
        client_ws = _FakeWebSocket()
        bridge = AuthenticatedPeer(
            device_id="device",
            role="bridge",
            ws=bridge_ws,
            device=self.device,
            session_bundle={"sessionPublicKey": "a", "sessionNonce": "b", "signature": "c", "signedAt": 1},
        )
        client = AuthenticatedPeer(
            device_id="device",
            role="client",
            ws=client_ws,
            device=self.device,
            session_bundle={"sessionPublicKey": "d", "sessionNonce": "e", "signature": "f", "signedAt": 1},
        )
        self.assertIsNone(await runtime.register(bridge))
        session = await runtime.register(client)
        assert session is not None

        await runtime.unregister("device", "bridge", bridge_ws)

        self.assertEqual(
            client_ws.json_messages,
            [
                {
                    "deviceId": "device",
                    "reason": "peer_disconnected",
                    "sessionId": session.session_id,
                    "type": "close_session",
                }
            ],
        )
