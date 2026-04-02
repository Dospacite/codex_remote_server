from __future__ import annotations

import unittest
from unittest import mock

from aiohttp import web

from codex_remote_server.__main__ import build_parser
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
        self.assertIsNone(await runtime.register(bridge, max_concurrent_clients=10))
        session = await runtime.register(client, max_concurrent_clients=10)
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
        self.assertIsNone(await runtime.register(bridge, max_concurrent_clients=10))
        session = await runtime.register(client, max_concurrent_clients=10)
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

    async def test_register_rejects_new_client_when_limit_reached(self) -> None:
        runtime = RelayRuntime()
        bridge_one = AuthenticatedPeer(
            device_id="device-1",
            role="bridge",
            ws=_FakeWebSocket(),
            device=self.device,
            session_bundle={"sessionPublicKey": "a", "sessionNonce": "b", "signature": "c", "signedAt": 1},
        )
        client_one = AuthenticatedPeer(
            device_id="device-1",
            role="client",
            ws=_FakeWebSocket(),
            device=self.device,
            session_bundle={"sessionPublicKey": "d", "sessionNonce": "e", "signature": "f", "signedAt": 1},
        )
        second_device = DeviceRecord(
            device_id="device-2",
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
        bridge_two = AuthenticatedPeer(
            device_id="device-2",
            role="bridge",
            ws=_FakeWebSocket(),
            device=second_device,
            session_bundle={"sessionPublicKey": "g", "sessionNonce": "h", "signature": "i", "signedAt": 1},
        )
        client_two = AuthenticatedPeer(
            device_id="device-2",
            role="client",
            ws=_FakeWebSocket(),
            device=second_device,
            session_bundle={"sessionPublicKey": "j", "sessionNonce": "k", "signature": "l", "signedAt": 1},
        )

        self.assertIsNone(await runtime.register(bridge_one, max_concurrent_clients=1))
        self.assertIsNotNone(await runtime.register(client_one, max_concurrent_clients=1))
        self.assertIsNone(await runtime.register(bridge_two, max_concurrent_clients=1))

        with self.assertRaises(web.HTTPTooManyRequests):
            await runtime.register(client_two, max_concurrent_clients=1)


class ParserTests(unittest.TestCase):
    def test_public_base_url_defaults_from_environment(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"CODEX_REMOTE_RELAY_PUBLIC_BASE_URL": "https://relay.actual.example"},
            clear=False,
        ):
            parser = build_parser()
            args = parser.parse_args([])
        self.assertEqual(args.public_base_url, "https://relay.actual.example")
