"""Local user, invite, and per-site access state for the central SSO."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from pathlib import Path

PASSWORD_ROUNDS = 310_000
INVITE_TTL = 24 * 60 * 60
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


def normalized_host(host: str) -> str | None:
    value = host.strip().lower().rstrip(".")
    if not HOST_RE.fullmatch(value) or not value.endswith(".bezrabotnyi.com"):
        return None
    return value


def valid_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username))


def connect(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize(path: str | Path, site_hosts, legacy_users) -> None:
    """Create the durable schema and preserve the single legacy owner login."""
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with connect(target) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                display_name TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ("pending","active","disabled")),
                is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
                legacy INTEGER NOT NULL DEFAULT 0 CHECK(legacy IN (0,1)),
                password_salt TEXT,
                password_hash TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sites (
                host TEXT PRIMARY KEY,
                label TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_sites (
                username TEXT NOT NULL COLLATE NOCASE REFERENCES users(username) ON DELETE CASCADE,
                host TEXT NOT NULL REFERENCES sites(host) ON DELETE CASCADE,
                PRIMARY KEY(username, host)
            );
            CREATE TABLE IF NOT EXISTS invites (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE REFERENCES users(username) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        for raw_host in site_hosts:
            host = normalized_host(str(raw_host))
            if host:
                db.execute("INSERT OR IGNORE INTO sites(host,label) VALUES(?,?)", (host, host))
        seeded = db.execute("SELECT value FROM metadata WHERE key=?", ("legacy_admin_seeded",)).fetchone()
        if not seeded:
            legacy_names = sorted(legacy_users)
            if len(legacy_names) == 1 and valid_username(legacy_names[0]):
                username = legacy_names[0]
                db.execute(
                    "INSERT OR IGNORE INTO users(username,display_name,status,is_admin,legacy,created_at) "
                    "VALUES(?,?, ?,1,1,?)",
                    (username, username, "active", int(time.time())),
                )
            db.execute(
                "INSERT INTO metadata(key,value) VALUES(?,?)", ("legacy_admin_seeded", "1")
            )
    target.chmod(0o600)


def password_digest(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ROUNDS, dklen=32)
    return base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, salt_text: str, digest_text: str) -> bool:
    try:
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ROUNDS, dklen=32)
    return hmac.compare_digest(actual, expected)


def get_user(path: str | Path, username: str):
    with connect(path) as db:
        row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None


def managed_password_hashes(path: str | Path) -> dict[str, str]:
    with connect(path) as db:
        rows = db.execute(
            "SELECT username,password_salt,password_hash FROM users "
            "WHERE status='active' AND legacy=0 AND password_salt IS NOT NULL AND password_hash IS NOT NULL"
        ).fetchall()
        return {
            row["username"]: "$managed$" + row["password_salt"] + "$" + row["password_hash"]
            for row in rows
        }


def can_access(path: str | Path, username: str, host: str) -> bool:
    site = normalized_host(host)
    if not site:
        return False
    with connect(path) as db:
        user = db.execute(
            "SELECT status,is_admin FROM users WHERE username=?", (username,)
        ).fetchone()
        if not user or user["status"] != "active":
            return False
        if user["is_admin"]:
            return True
        return db.execute(
            "SELECT 1 FROM sites s JOIN user_sites u USING(host) "
            "WHERE s.host=? AND u.username=?",
            (site, username),
        ).fetchone() is not None


def list_sites(path: str | Path) -> list[str]:
    with connect(path) as db:
        return [row[0] for row in db.execute("SELECT host FROM sites ORDER BY host")]


def list_users(path: str | Path) -> list[dict]:
    with connect(path) as db:
        rows = db.execute(
            "SELECT username,display_name,status,is_admin,legacy,created_at FROM users "
            "ORDER BY is_admin DESC, display_name COLLATE NOCASE, username COLLATE NOCASE"
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["sites"] = [
                site[0]
                for site in db.execute(
                    "SELECT host FROM user_sites WHERE username=? ORDER BY host", (item["username"],)
                )
            ]
            result.append(item)
        return result


def invite_info(path: str | Path, token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    with connect(path) as db:
        row = db.execute(
            "SELECT i.expires_at,u.username,u.display_name,u.status FROM invites i "
            "JOIN users u USING(username) WHERE i.token_hash=? AND i.used_at IS NULL AND i.expires_at>=?",
            (token_hash, now),
        ).fetchone()
        return dict(row) if row and row["status"] == "pending" else None


def is_admin(path: str | Path, username: str) -> bool:
    with connect(path) as db:
        row = db.execute(
            "SELECT 1 FROM users WHERE username=? AND status=? AND is_admin=1",
            (username, "active"),
        ).fetchone()
        return row is not None


def create_invite(path: str | Path, username: str, display_name: str, selected_sites, ttl: int = INVITE_TTL):
    username = username.strip()
    display_name = display_name.strip()[:100] or username
    if not valid_username(username):
        raise ValueError("invalid username")
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "INSERT INTO users(username,display_name,status,is_admin,legacy,created_at) "
                "VALUES(?,?, ?,0,0,?)",
                (username, display_name, "pending", now),
            )
            allowed_sites = set(list_sites(path))
            wanted = {normalized_host(str(host)) for host in selected_sites}
            wanted.discard(None)
            if not wanted.issubset(allowed_sites):
                raise ValueError("unknown site")
            db.executemany(
                "INSERT INTO user_sites(username,host) VALUES(?,?)",
                [(username, host) for host in sorted(wanted)],
            )
            db.execute(
                "INSERT INTO invites(token_hash,username,expires_at) VALUES(?,?,?)",
                (token_hash, username, now + ttl),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
    return token, now + ttl


def consume_invite(path: str | Path, token: str, password: str) -> str | None:
    if len(password) < 12 or len(password) > 1024:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    salt, digest = password_digest(password)
    now = int(time.time())
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        invite = db.execute(
            "SELECT token_hash,username FROM invites WHERE token_hash=? AND used_at IS NULL AND expires_at>=?",
            (token_hash, now),
        ).fetchone()
        if not invite:
            db.rollback()
            return None
        user = db.execute(
            "SELECT status FROM users WHERE username=?", (invite["username"],)
        ).fetchone()
        if not user or user["status"] != "pending":
            db.rollback()
            return None
        db.execute(
            "UPDATE users SET status=?,password_salt=?,password_hash=? WHERE username=?",
            ("active", salt, digest, invite["username"]),
        )
        db.execute("UPDATE invites SET used_at=? WHERE token_hash=?", (now, token_hash))
        db.commit()
        return invite["username"]


def update_user(path: str | Path, username: str, selected_sites, status: str | None = None) -> bool:
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute(
            "SELECT is_admin,password_hash,legacy,status FROM users WHERE username=?", (username,)
        ).fetchone()
        if not user or user["is_admin"]:
            db.rollback()
            return False
        if status == "active" and not user["legacy"] and not user["password_hash"]:
            db.rollback()
            return False
        if status == "pending" and (user["password_hash"] or user["legacy"]):
            db.rollback()
            return False
        allowed_sites = {row[0] for row in db.execute("SELECT host FROM sites")}
        wanted = {normalized_host(str(host)) for host in selected_sites}
        wanted.discard(None)
        if not wanted.issubset(allowed_sites):
            db.rollback()
            return False
        db.execute("DELETE FROM user_sites WHERE username=?", (username,))
        db.executemany(
            "INSERT INTO user_sites(username,host) VALUES(?,?)",
            [(username, host) for host in sorted(wanted)],
        )
        if status in ("active", "disabled", "pending"):
            db.execute("UPDATE users SET status=? WHERE username=?", (status, username))
        db.commit()
        return True
