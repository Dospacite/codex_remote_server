from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def canonical_json(data: dict[str, object]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def utc_now() -> int:
    return int(time.time())


def random_token(length: int = 32) -> str:
    return b64url_encode(secrets.token_bytes(length))


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def scrypt_hash(secret: str, *, salt: bytes) -> str:
    digest = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return b64url_encode(digest)


def verify_scrypt_hash(secret: str, *, salt: bytes, expected: str) -> bool:
    computed = scrypt_hash(secret, salt=salt)
    return secrets.compare_digest(computed, expected)


def load_public_signing_key(value: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(value))


def is_valid_public_signing_key(value: str) -> bool:
    try:
        load_public_signing_key(value)
        return True
    except ValueError:
        return False


def verify_signature(
    public_key: str,
    signature: str,
    message: bytes,
) -> bool:
    try:
        load_public_signing_key(public_key).verify(b64url_decode(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def fingerprint_public_key(public_key: str) -> str:
    digest = hashlib.sha256(b64url_decode(public_key)).digest()[:10]
    return b64url_encode(digest)


def session_bundle_payload(
    *,
    device_id: str,
    role: str,
    session_public_key: str,
    session_nonce: str,
    signed_at: int,
) -> bytes:
    return canonical_json(
        {
            "deviceId": device_id,
            "role": role,
            "sessionNonce": session_nonce,
            "sessionPublicKey": session_public_key,
            "signedAt": signed_at,
            "type": "codex-remote-session-bundle-v1",
        }
    )


def auth_payload(
    *,
    challenge: str,
    connection_id: str,
    device_id: str,
    role: str,
    auth_nonce: str,
    auth_timestamp: int,
) -> bytes:
    return canonical_json(
        {
            "authNonce": auth_nonce,
            "authTimestamp": auth_timestamp,
            "challenge": challenge,
            "connectionId": connection_id,
            "deviceId": device_id,
            "role": role,
            "type": "codex-remote-auth-v1",
        }
    )


@dataclass(slots=True)
class PairingCodePayload:
    device_id: str
    relay_url: str
    claim_token: str
    bridge_signing_public_key: str
    bridge_label: str
    expires_at: int

    def encode(self) -> str:
        return "crp1." + b64url_encode(
            canonical_json(
                {
                    "bridgeLabel": self.bridge_label,
                    "bridgeSigningPublicKey": self.bridge_signing_public_key,
                    "claimToken": self.claim_token,
                    "deviceId": self.device_id,
                    "expiresAt": self.expires_at,
                    "relayUrl": self.relay_url,
                    "type": "codex-remote-pairing-v1",
                }
            )
        )

    @classmethod
    def decode(cls, value: str) -> "PairingCodePayload":
        prefix = "crp1."
        if not value.startswith(prefix):
            raise ValueError("Unsupported pairing code format.")
        raw = json.loads(b64url_decode(value[len(prefix) :]))
        if raw.get("type") != "codex-remote-pairing-v1":
            raise ValueError("Unsupported pairing code payload.")
        return cls(
            device_id=str(raw["deviceId"]),
            relay_url=str(raw["relayUrl"]),
            claim_token=str(raw["claimToken"]),
            bridge_signing_public_key=str(raw["bridgeSigningPublicKey"]),
            bridge_label=str(raw.get("bridgeLabel") or ""),
            expires_at=int(raw["expiresAt"]),
        )


def generate_private_signing_key_pem() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
