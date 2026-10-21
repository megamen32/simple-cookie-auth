"""WebAuthn credential storage and challenge handling for cookie_auth.py.

Passkeys are optional: the recovery ingress deliberately leaves them disabled.
Private keys stay in the authenticator; this module stores public credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


RP_ID = "auth.bezrabotnyi.com"
ORIGIN = "https://auth.bezrabotnyi.com"
DB_PATH = Path(os.environ.get(
    "GPTADMIN_COOKIE_AUTH_PASSKEY_DB",
    "/etc/gptadmin-cookie-auth/passkeys.sqlite3",
))
READY_PATH = Path(str(DB_PATH) + ".initialized")
CHALLENGE_TTL_SECONDS = 120
MAX_PENDING_CHALLENGES = 512


class PasskeyStoreError(RuntimeError):
    """The passkey store is absent, corrupt, or not safely initialized."""


_challenge_lock = threading.Lock()
_challenges: dict[str, dict[str, Any]] = {}


def _connect(*, initialize: bool = False) -> sqlite3.Connection:
    """Open a validated store without silently recreating lost state."""
    if not DB_PATH.exists():
        if READY_PATH.exists() or not initialize:
            raise PasskeyStoreError("passkey store unavailable")
        DB_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(DB_PATH.parent, 0o700)
        try:
            fd = os.open(DB_PATH, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
    elif not READY_PATH.exists():
        raise PasskeyStoreError("passkey store state is incomplete")

    try:
        conn = sqlite3.connect(DB_PATH, timeout=3, isolation_level=None)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        if initialize and not READY_PATH.exists():
            conn.executescript(
                "BEGIN IMMEDIATE;"
                "CREATE TABLE principals ("
                " username TEXT PRIMARY KEY, generation BLOB NOT NULL, user_handle BLOB NOT NULL"
                ");"
                "CREATE TABLE credentials ("
                " credential_id BLOB NOT NULL PRIMARY KEY, username TEXT NOT NULL,"
                " generation BLOB NOT NULL, user_handle BLOB NOT NULL,"
                " public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,"
                " label TEXT NOT NULL, created_at INTEGER NOT NULL,"
                " last_used_at INTEGER NOT NULL DEFAULT 0, backed_up INTEGER NOT NULL DEFAULT 0,"
                " user_agent TEXT NOT NULL DEFAULT '', logical_cores INTEGER"
                ");"
                "CREATE INDEX credentials_user_idx ON credentials(username, generation);"
                "COMMIT;"
            )
            marker_tmp = READY_PATH.with_name(READY_PATH.name + "." + secrets.token_hex(8) + ".tmp")
            fd = os.open(marker_tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as marker:
                marker.write(b"passkey-store-v1\n")
                marker.flush()
                os.fsync(marker.fileno())
            os.replace(marker_tmp, READY_PATH)
            dir_fd = os.open(READY_PATH.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        elif READY_PATH.exists():
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('principals','credentials')"
            ).fetchall()
            if {row[0] for row in rows} != {"principals", "credentials"}:
                conn.close()
                raise PasskeyStoreError("passkey store schema is invalid")
            # Upgrade existing credential stores in place without replacing or
            # weakening the initialized store. SQLite serializes this migration.
            conn.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(credentials)")}
            if "user_agent" not in columns:
                conn.execute("ALTER TABLE credentials ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''")
            if "logical_cores" not in columns:
                conn.execute("ALTER TABLE credentials ADD COLUMN logical_cores INTEGER")
            conn.execute("COMMIT")
        os.chmod(DB_PATH, 0o600)
        return conn
    except PasskeyStoreError:
        raise
    except Exception as exc:
        raise PasskeyStoreError("passkey store unavailable") from exc


def account_generation(signing_secret: bytes, username: str, password_hash: str) -> bytes:
    """Bind credentials to the current htpasswd account incarnation.

    A password-hash change requires passkey re-enrollment. The raw htpasswd
    hash is never copied into the passkey database.
    """
    message = b"passkey-account-v1\0" + username.encode() + b"\0" + password_hash.encode()
    return hmac.new(signing_secret, message, hashlib.sha256).digest()


def principal_for_registration(username: str, generation: bytes) -> tuple[bytes, list[bytes]]:
    """Return a stable opaque handle and credentials to exclude on re-enroll."""
    conn = _connect(initialize=True)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT generation, user_handle FROM principals WHERE username=?", (username,)
        ).fetchone()
        if row is None:
            handle = secrets.token_bytes(32)
            conn.execute(
                "INSERT INTO principals(username,generation,user_handle) VALUES(?,?,?)",
                (username, generation, handle),
            )
        elif not hmac.compare_digest(row[0], generation):
            handle = secrets.token_bytes(32)
            conn.execute("DELETE FROM credentials WHERE username=?", (username,))
            conn.execute(
                "UPDATE principals SET generation=?,user_handle=? WHERE username=?",
                (generation, handle, username),
            )
        else:
            handle = row[1]
        ids = [r[0] for r in conn.execute(
            "SELECT credential_id FROM credentials WHERE username=? AND generation=?",
            (username, generation),
        ).fetchall()]
        conn.execute("COMMIT")
        return handle, ids
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise PasskeyStoreError("passkey store unavailable") from exc
    finally:
        conn.close()


def save_credential(
    *, credential_id: bytes, username: str, generation: bytes, user_handle: bytes,
    public_key: bytes, sign_count: int, label: str, backed_up: bool,
    user_agent: str = "", logical_cores: int | None = None,
) -> bool:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        principal = conn.execute(
            "SELECT generation,user_handle FROM principals WHERE username=?", (username,)
        ).fetchone()
        if (principal is None or not hmac.compare_digest(principal[0], generation)
                or not hmac.compare_digest(principal[1], user_handle)):
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "INSERT INTO credentials(credential_id,username,generation,user_handle,public_key,"
            "sign_count,label,created_at,backed_up,user_agent,logical_cores) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (credential_id, username, generation, user_handle, public_key, sign_count,
             label, int(time.time()), int(backed_up), user_agent, logical_cores),
        )
        conn.execute("COMMIT")
        return True
    except sqlite3.IntegrityError:
        try: conn.execute("ROLLBACK")
        except sqlite3.Error: pass
        return False
    except Exception as exc:
        try: conn.execute("ROLLBACK")
        except sqlite3.Error: pass
        raise PasskeyStoreError("passkey store unavailable") from exc
    finally:
        conn.close()


def list_credentials(username: str, generation: bytes) -> list[dict[str, Any]]:
    if not DB_PATH.exists() and not READY_PATH.exists():
        return []
    conn = _connect()
    try:
        return [
            {"credential_id": row[0], "label": row[1], "created_at": row[2],
             "last_used_at": row[3], "backed_up": bool(row[4]),
             "user_agent": row[5], "logical_cores": row[6]}
            for row in conn.execute(
                "SELECT credential_id,label,created_at,last_used_at,backed_up,user_agent,logical_cores "
                "FROM credentials "
                "WHERE username=? AND generation=? ORDER BY created_at",
                (username, generation),
            ).fetchall()
        ]
    except Exception as exc:
        raise PasskeyStoreError("passkey store unavailable") from exc
    finally:
        conn.close()


def get_credential(credential_id: bytes) -> dict[str, Any] | None:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT credential_id,username,generation,user_handle,public_key,sign_count "
            "FROM credentials WHERE credential_id=?", (credential_id,),
        ).fetchone()
        if row is None:
            return None
        return {"credential_id": row[0], "username": row[1], "generation": row[2],
                "user_handle": row[3], "public_key": row[4], "sign_count": row[5]}
    except Exception as exc:
        raise PasskeyStoreError("passkey store unavailable") from exc
    finally:
        conn.close()


def record_success(credential_id: bytes, old_count: int, new_count: int) -> bool:
    """Commit counter and last-used time only if the record stayed unchanged."""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            "UPDATE credentials SET sign_count=?,last_used_at=? "
            "WHERE credential_id=? AND sign_count=?",
            (new_count, int(time.time()), credential_id, old_count),
        )
        if cursor.rowcount != 1:
            conn.execute("ROLLBACK")
            return False
        conn.execute("COMMIT")
        return True
    except Exception as exc:
        try: conn.execute("ROLLBACK")
        except sqlite3.Error: pass
        raise PasskeyStoreError("passkey store unavailable") from exc
    finally:
        conn.close()


def revoke_credential(username: str, generation: bytes, credential_id: bytes) -> bool:
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            "DELETE FROM credentials WHERE username=? AND generation=? AND credential_id=?",
            (username, generation, credential_id),
        )
        conn.execute("COMMIT")
        return cursor.rowcount == 1
    except Exception as exc:
        try: conn.execute("ROLLBACK")
        except sqlite3.Error: pass
        raise PasskeyStoreError("passkey store unavailable") from exc
    finally:
        conn.close()


def create_challenge(operation: str, state: dict[str, Any]) -> tuple[str, bytes]:
    now = time.time()
    transaction_id = secrets.token_urlsafe(32)
    challenge = secrets.token_bytes(32)
    with _challenge_lock:
        for key in [k for k, value in _challenges.items() if value["expires"] < now]:
            del _challenges[key]
        if len(_challenges) >= MAX_PENDING_CHALLENGES:
            raise PasskeyStoreError("too many pending ceremonies")
        _challenges[transaction_id] = {
            **state, "operation": operation, "challenge": challenge,
            "expires": now + CHALLENGE_TTL_SECONDS,
        }
    return transaction_id, challenge


def consume_challenge(transaction_id: str, operation: str) -> dict[str, Any] | None:
    with _challenge_lock:
        entry = _challenges.pop(transaction_id, None)
    if not entry or entry["expires"] < time.time() or entry["operation"] != operation:
        return None
    return entry


def webauthn_api():
    """Lazy import keeps recovery password login independent of this package."""
    try:
        import webauthn
        from webauthn.helpers.structs import (
            AttestationConveyancePreference, AuthenticatorAttachment,
            AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
            ResidentKeyRequirement, UserVerificationRequirement,
        )
    except ImportError as exc:
        raise PasskeyStoreError("passkey support unavailable") from exc
    return (webauthn, AttestationConveyancePreference, AuthenticatorAttachment,
            AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
            ResidentKeyRequirement, UserVerificationRequirement)
