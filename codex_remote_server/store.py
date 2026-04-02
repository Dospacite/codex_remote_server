from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .security import fingerprint_public_key, random_token, scrypt_hash, utc_now, verify_scrypt_hash


@dataclass(slots=True)
class DeviceRecord:
    device_id: str
    bridge_label: str
    bridge_signing_public_key: str
    bridge_fingerprint: str
    client_signing_public_key: str | None
    client_label: str | None
    claim_token_hash: str | None
    claim_token_salt: str | None
    claim_expires_at: int | None
    claimed_at: int | None


class DeviceStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    bridge_label TEXT NOT NULL,
                    bridge_signing_public_key TEXT NOT NULL,
                    bridge_fingerprint TEXT NOT NULL,
                    client_signing_public_key TEXT,
                    client_label TEXT,
                    claim_token_hash TEXT,
                    claim_token_salt TEXT,
                    claim_expires_at INTEGER,
                    created_at INTEGER NOT NULL,
                    claimed_at INTEGER
                )
                """
            )

    def enroll_device(
        self,
        *,
        bridge_label: str,
        bridge_signing_public_key: str,
        claim_ttl_seconds: int,
    ) -> tuple[DeviceRecord, str]:
        device_id = random_token(18)
        claim_token = random_token(24)
        claim_salt = random_token(16)
        now = utc_now()
        record = DeviceRecord(
            device_id=device_id,
            bridge_label=bridge_label,
            bridge_signing_public_key=bridge_signing_public_key,
            bridge_fingerprint=fingerprint_public_key(bridge_signing_public_key),
            client_signing_public_key=None,
            client_label=None,
            claim_token_hash=scrypt_hash(claim_token, salt=claim_salt.encode("utf-8")),
            claim_token_salt=claim_salt,
            claim_expires_at=now + claim_ttl_seconds,
            claimed_at=None,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO devices (
                    device_id,
                    bridge_label,
                    bridge_signing_public_key,
                    bridge_fingerprint,
                    claim_token_hash,
                    claim_token_salt,
                    claim_expires_at,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.device_id,
                    record.bridge_label,
                    record.bridge_signing_public_key,
                    record.bridge_fingerprint,
                    record.claim_token_hash,
                    record.claim_token_salt,
                    record.claim_expires_at,
                    now,
                ),
            )
        return record, claim_token

    def get_device(self, device_id: str) -> DeviceRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    device_id,
                    bridge_label,
                    bridge_signing_public_key,
                    bridge_fingerprint,
                    client_signing_public_key,
                    client_label,
                    claim_token_hash,
                    claim_token_salt,
                    claim_expires_at,
                    claimed_at
                FROM devices
                WHERE device_id = ?
                """,
                (device_id,),
            ).fetchone()
        if row is None:
            return None
        return DeviceRecord(
            device_id=row["device_id"],
            bridge_label=row["bridge_label"],
            bridge_signing_public_key=row["bridge_signing_public_key"],
            bridge_fingerprint=row["bridge_fingerprint"],
            client_signing_public_key=row["client_signing_public_key"],
            client_label=row["client_label"],
            claim_token_hash=row["claim_token_hash"],
            claim_token_salt=row["claim_token_salt"],
            claim_expires_at=row["claim_expires_at"],
            claimed_at=row["claimed_at"],
        )

    def claim_device(
        self,
        *,
        device_id: str,
        claim_token: str,
        client_signing_public_key: str,
        client_label: str,
    ) -> DeviceRecord:
        record = self.get_device(device_id)
        if record is None:
            raise ValueError("Unknown device.")
        if record.claim_token_hash is None or record.claim_token_salt is None:
            raise ValueError("This device is not accepting pairing requests.")
        now = utc_now()
        if record.claim_expires_at is None or record.claim_expires_at < now:
            raise ValueError("The pairing code has expired.")
        if not verify_scrypt_hash(
            claim_token,
            salt=record.claim_token_salt.encode("utf-8"),
            expected=record.claim_token_hash,
        ):
            raise ValueError("Invalid pairing code.")
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE devices
                SET
                    client_signing_public_key = ?,
                    client_label = ?,
                    claim_token_hash = NULL,
                    claim_token_salt = NULL,
                    claim_expires_at = NULL,
                    claimed_at = ?
                WHERE device_id = ?
                """,
                (
                    client_signing_public_key,
                    client_label,
                    now,
                    device_id,
                ),
            )
        claimed = self.get_device(device_id)
        assert claimed is not None
        return claimed
