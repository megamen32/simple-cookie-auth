#!/usr/bin/env python3
"""A deliberately small cookie login service for reverse proxies."""

from __future__ import annotations

import argparse
import base64
import crypt
import hashlib
import hmac
import html
import http.server
import json
import os
import secrets
import subprocess
import time
import urllib.parse
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path


@dataclass(frozen=True)
class Config:
    """Runtime settings for the auth service."""

    host: str
    port: int
    users_file: Path
    secret_file: Path
    cookie_name: str
    cookie_domain: str
    session_ttl: int
    default_redirect: str

    @property
    def base_domain(self) -> str:
        return self.cookie_domain.lstrip(".").lower()


def parse_args() -> Config:
    """Read CLI options, with environment variables as convenient defaults."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.getenv("SIMPLE_COOKIE_AUTH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SIMPLE_COOKIE_AUTH_PORT", "18991")))
    parser.add_argument(
        "--users",
        type=Path,
        default=Path(os.getenv("SIMPLE_COOKIE_AUTH_USERS", "./users.htpasswd")),
    )
    parser.add_argument(
        "--secret",
        type=Path,
        default=Path(os.getenv("SIMPLE_COOKIE_AUTH_SECRET", "./secret")),
    )
    parser.add_argument(
        "--cookie-domain",
        default=os.getenv("SIMPLE_COOKIE_AUTH_COOKIE_DOMAIN", ".example.com"),
    )
    parser.add_argument(
        "--cookie-name",
        default=os.getenv("SIMPLE_COOKIE_AUTH_COOKIE_NAME", "simple_auth"),
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=int(os.getenv("SIMPLE_COOKIE_AUTH_TTL", str(8 * 3600))),
        help="Cookie lifetime in seconds.",
    )
    parser.add_argument(
        "--default-redirect",
        default=os.getenv("SIMPLE_COOKIE_AUTH_DEFAULT_REDIRECT", "https://example.com/"),
    )
    args = parser.parse_args()
    return Config(
        host=args.host,
        port=args.port,
        users_file=args.users,
        secret_file=args.secret,
        cookie_name=args.cookie_name,
        cookie_domain=args.cookie_domain,
        session_ttl=args.ttl,
        default_redirect=args.default_redirect,
    )


def read_secret(config: Config) -> bytes:
    """Read a non-empty signing secret; missing secrets are a hard failure."""
    secret = config.secret_file.read_bytes().strip()
    if not secret:
        raise RuntimeError(f"empty auth secret: {config.secret_file}")
    return secret


def read_users(config: Config) -> dict[str, str]:
    """Read Apache htpasswd-compatible username and password-hash pairs."""
    users: dict[str, str] = {}
    for raw_line in config.users_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and ":" in line:
            username, password_hash = line.split(":", 1)
            users[username] = password_hash
    return users


def verify_password(config: Config, username: str, password: str) -> bool:
    """Verify APR1, SHA-crypt, or bcrypt hashes supported by the host crypt library."""
    stored = read_users(config).get(username)
    if not stored:
        return False
    if stored.startswith("$apr1$"):
        try:
            salt = stored.split("$")[2]
        except IndexError:
            return False
        result = subprocess.run(
            ["openssl", "passwd", "-apr1", "-salt", salt, "-stdin"],
            input=(password + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        return hmac.compare_digest(result.stdout.decode().strip(), stored)
    try:
        return hmac.compare_digest(crypt.crypt(password, stored), stored)
    except (OSError, ValueError):
        return False


def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign(config: Config, payload: bytes) -> str:
    return encode(hmac.new(read_secret(config), payload, hashlib.sha256).digest())


def make_token(config: Config, username: str) -> str:
    payload = json.dumps(
        {
            "u": username,
            "e": int(time.time()) + config.session_ttl,
            "n": secrets.token_urlsafe(16),
        },
        separators=(",", ":"),
    ).encode()
    body = encode(payload)
    return f"{body}.{sign(config, body.encode())}"


def check_token(config: Config, token: str) -> str | None:
    """Return the signed username or None for any malformed, forged, or expired token."""
    try:
        body, signature = token.split(".", 1)
        if not hmac.compare_digest(sign(config, body.encode()), signature):
            return None
        payload = json.loads(decode(body))
        if int(payload.get("e", 0)) < int(time.time()):
            return None
        username = payload.get("u")
        return username if isinstance(username, str) and username else None
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError, RuntimeError):
        return None


def parse_cookies(header: str) -> dict[str, str]:
    """Parse cookies without letting a later duplicate replace the first value."""
    cookies: dict[str, str] = {}
    for part in (header or "").split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            cookies.setdefault(key.strip(), value.strip())
    return cookies


def safe_redirect(config: Config, target: str) -> str:
    """Allow redirects only to the configured domain or to a relative path."""
    if not target:
        return config.default_redirect
    try:
        parsed = urllib.parse.urlparse(target)
        host = (parsed.hostname or "").lower()
        if parsed.scheme in ("http", "https") and (
            host == config.base_domain or host.endswith("." + config.base_domain)
        ):
            return target
        if target.startswith("/"):
            return target
    except ValueError:
        pass
    return config.default_redirect


def login_page(config: Config, target: str, error: bool = False) -> bytes:
    error_html = '<p class="error">Wrong username or password</p>' if error else ""
    escaped_target = html.escape(target, quote=True)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login</title>
<style>body{{font:16px system-ui;background:#111;color:#eee;display:grid;place-items:center;min-height:100vh}}
form{{background:#1c1c1c;padding:2rem;border-radius:1rem;width:min(22rem,calc(100vw - 2rem))}}
input,button{{box-sizing:border-box;width:100%;padding:.75rem;margin:.4rem 0;border-radius:.5rem;border:1px solid #555;background:#0d0d0d;color:#fff}}
button{{background:#2864d7;border:0;font-weight:700}}.error{{color:#ff8585}}</style></head>
<body><form method="post" action="/login"><h2>Login</h2>{error_html}
<input name="username" autocomplete="username" placeholder="username" autofocus>
<input name="password" type="password" autocomplete="current-password" placeholder="password">
<input type="hidden" name="rd" value="{escaped_target}"><button>Sign in</button></form></body></html>""".encode()


class Handler(http.server.BaseHTTPRequestHandler):
    """HTTP endpoints consumed by the browser and reverse proxy."""

    server_version = "simple-cookie-auth/1.0"

    def __init__(self, request, client_address, server, config: Config):
        self.config = config
        super().__init__(request, client_address, server)

    def log_message(self, fmt: str, *args: object) -> None:
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def current_user(self) -> str | None:
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        return check_token(self.config, cookies.get(self.config.cookie_name, ""))

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/healthz":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        if parsed.path == "/check":
            user = self.current_user()
            self.send_response(HTTPStatus.NO_CONTENT if user else HTTPStatus.UNAUTHORIZED)
            if user:
                self.send_header("X-Auth-User", user)
            self.end_headers()
            return
        if parsed.path == "/logout":
            self.send_response(HTTPStatus.FOUND)
            self.send_header(
                "Set-Cookie",
                f"{self.config.cookie_name}=; Domain={self.config.cookie_domain}; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
            )
            self.send_header("Location", safe_redirect(self.config, query.get("rd", ["/"])[0]))
            self.end_headers()
            return
        if parsed.path in ("/", "/login"):
            target = safe_redirect(self.config, query.get("rd", [self.config.default_redirect])[0])
            body = login_page(self.config, target, query.get("error", [""])[0] == "1")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if urllib.parse.urlparse(self.path).path != "/login":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 16 * 1024:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        form = urllib.parse.parse_qs(self.rfile.read(length).decode(errors="replace"))
        username = form.get("username", [""])[0].strip()
        password = form.get("password", [""])[0]
        target = safe_redirect(self.config, form.get("rd", [self.config.default_redirect])[0])
        if verify_password(self.config, username, password):
            self.send_response(HTTPStatus.FOUND)
            self.send_header(
                "Set-Cookie",
                f"{self.config.cookie_name}={make_token(self.config, username)}; Domain={self.config.cookie_domain}; Path=/; Max-Age={self.config.session_ttl}; Secure; HttpOnly; SameSite=Lax",
            )
            self.send_header("Location", target)
        else:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/login?error=1&rd=" + urllib.parse.quote(target, safe=""))
        self.end_headers()


class ConfiguredHTTPServer(http.server.ThreadingHTTPServer):
    """Threading server that passes immutable configuration to each handler."""

    def __init__(self, address, config: Config):
        super().__init__(address, lambda *args: Handler(*args, config))


def main() -> None:
    config = parse_args()
    server = ConfiguredHTTPServer((config.host, config.port), config)
    print(f"simple-cookie-auth listening on {config.host}:{config.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
