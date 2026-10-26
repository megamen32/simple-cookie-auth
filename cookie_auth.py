#!/usr/bin/env python3
"""Small self-hosted cookie auth service shared by primary and recovery ingress."""

import base64
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
from pathlib import Path
from http import HTTPStatus

import access_control


HOST = os.environ.get("GPTADMIN_COOKIE_AUTH_HOST", "127.0.0.1")
PORT = int(os.environ.get("GPTADMIN_COOKIE_AUTH_PORT", "18991"))
HTPASSWD = os.environ.get("GPTADMIN_COOKIE_AUTH_HTPASSWD", "/data/auth-users")
SECRET_FILE = os.environ.get("GPTADMIN_COOKIE_AUTH_SECRET_FILE", "/data/auth-secret")
COOKIE_NAME = os.environ.get("GPTADMIN_COOKIE_AUTH_COOKIE", "gptadmin_auth")
COOKIE_DOMAIN = os.environ.get("GPTADMIN_COOKIE_AUTH_DOMAIN", ".bezrabotnyi.com")
SESSION_TTL = int(os.environ.get("GPTADMIN_COOKIE_AUTH_TTL", str(30 * 24 * 3600)))
PASSKEYS_ENABLED = os.environ.get("GPTADMIN_COOKIE_AUTH_PASSKEYS_ENABLED", "0") == "1"
CSRF_COOKIE = "__Host-gptadmin-csrf"
CSRF_COOKIE_PREFIX = CSRF_COOKIE + "-"
CEREMONY_COOKIE = "__Host-gptadmin-ceremony"
CSRF_TTL = 10 * 60
MAX_JSON_BODY = 64 * 1024
DEFAULT_REDIRECT = os.environ.get(
    "GPTADMIN_COOKIE_AUTH_DEFAULT_REDIRECT", "https://bezrabotnyi.com/"
)
LOGIN_FRAGMENT_SCRIPT = """function redirectWithLoginFragment(target) {
  const destination = new URL(target, location.href);
  if (!destination.href.includes('#') && location.hash) destination.hash = location.hash;
  return destination.href;
}"""
ACCESS_DB = os.environ.get(
    "GPTADMIN_COOKIE_AUTH_ACCESS_DB", "/var/lib/gptadmin-cookie-auth/access.sqlite3"
)
SITE_CATALOG_FILE = os.environ.get("GPTADMIN_COOKIE_AUTH_SITE_CATALOG", "/app/sites.json")
ADMIN_ENABLED = os.environ.get("GPTADMIN_COOKIE_AUTH_ADMIN_ENABLED", "1") == "1"
INVITE_SETUP_ENABLED = os.environ.get("GPTADMIN_COOKIE_AUTH_INVITE_SETUP_ENABLED", "1") == "1"


def read_site_catalog() -> list[str]:
    with open(SITE_CATALOG_FILE, "r", encoding="utf-8") as catalog_file:
        value = json.load(catalog_file)
    if not isinstance(value, list):
        raise RuntimeError("invalid SSO site catalog")
    return [str(host) for host in value]


def read_secret() -> bytes:
    """Read the signing secret and fail closed when it is absent or empty."""
    with open(SECRET_FILE, "rb") as secret_file:
        secret = secret_file.read().strip()
    if not secret:
        raise RuntimeError(f"empty auth secret: {SECRET_FILE}")
    return secret


def read_users() -> dict[str, str]:
    """Read legacy hashes and stable managed-account fingerprints for passkey binding."""
    users: dict[str, str] = {}
    with open(HTPASSWD, "r", encoding="utf-8") as users_file:
        for line in users_file:
            line = line.strip()
            if not line or ":" not in line:
                continue
            user, hashed = line.split(":", 1)
            users[user] = hashed
    try:
        users.update(access_control.managed_password_hashes(ACCESS_DB))
    except Exception:
        # The persistent account DB is created before the service starts. This
        # also lets bootstrap read the legacy file before the first DB exists.
        pass
    return users


def verify_apr1(password: str, stored: str) -> bool:
    """Verify Apache's APR1-MD5 htpasswd format using OpenSSL."""
    try:
        salt = stored.split("$")[2]
    except (IndexError, AttributeError):
        return False
    result = subprocess.run(
        ["openssl", "passwd", "-apr1", "-salt", salt, "-stdin"],
        input=(password + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )
    candidate = result.stdout.decode().strip()
    return hmac.compare_digest(candidate, stored)


def authenticate_password(username: str, password: str) -> str | None:
    """Verify an active managed account or the single legacy super-admin."""
    username = username.strip()
    users = read_users()
    if not username and users:
        username = next(iter(users))
    try:
        account = access_control.get_user(ACCESS_DB, username)
    except Exception:
        print("[auth] account store unavailable", flush=True)
        return None
    if not account or account["status"] != "active":
        return None
    if not account["legacy"]:
        if not account["password_salt"] or not account["password_hash"]:
            return None
        return username if access_control.verify_password(
            password, account["password_salt"], account["password_hash"]
        ) else None
    stored = users.get(username)
    if not stored:
        return None
    if stored.startswith("$apr1$"):
        return username if verify_apr1(password, stored) else None
    # Preserve the deployed SHA-crypt/bcrypt compatibility while the
    # canonical template catches up with the runtime.
    try:
        import crypt
        candidate = crypt.crypt(password, stored)
        return username if candidate and hmac.compare_digest(candidate, stored) else None
    except Exception:
        return None


def verify_password(username: str, password: str) -> bool:
    """Verify a login against the synchronized htpasswd file."""
    return authenticate_password(username, password) is not None


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign(payload: bytes) -> str:
    return b64(hmac.new(read_secret(), payload, hashlib.sha256).digest())


def make_token(username: str) -> str:
    expires = int(time.time()) + SESSION_TTL
    nonce = secrets.token_urlsafe(12)
    payload = json.dumps(
        {"u": username, "e": expires, "n": nonce}, separators=(",", ":")
    ).encode()
    body = b64(payload)
    return body + "." + sign(body.encode())


def check_token(token: str) -> str | None:
    try:
        body, signature = token.split(".", 1)
        if not hmac.compare_digest(sign(body.encode()), signature):
            return None
        data = json.loads(unb64(body))
        if int(data.get("e", 0)) < int(time.time()):
            return None
        return data.get("u") or "user"
    except (TypeError, ValueError, KeyError, json.JSONDecodeError, RuntimeError):
        return None


def parse_cookie(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in (header or "").split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def csrf_cookie_name_for_page() -> str:
    """Give each open auth page its own CSRF cookie so tabs do not invalidate each other."""
    return CSRF_COOKIE_PREFIX + secrets.token_urlsafe(12)


def valid_csrf_cookie_name(value: str) -> bool:
    if value == CSRF_COOKIE:
        return True  # Keep already-open pages from before a rolling deploy working.
    if not value.startswith(CSRF_COOKIE_PREFIX):
        return False
    suffix = value[len(CSRF_COOKIE_PREFIX):]
    return 16 <= len(suffix) <= 64 and all(ch.isalnum() or ch in "-_" for ch in suffix)


def safe_rd(redirect: str) -> str:
    """Allow redirects only within the managed domain or to a relative path."""
    if not redirect:
        return DEFAULT_REDIRECT
    try:
        parsed = urllib.parse.urlparse(redirect)
        host = (parsed.hostname or "").lower()
        if parsed.scheme in ("https", "http") and (
            host == "bezrabotnyi.com" or host.endswith(".bezrabotnyi.com")
        ):
            return redirect
        if redirect.startswith("/") and not redirect.startswith("//") and "\\" not in redirect:
            return redirect
    except ValueError:
        pass
    return DEFAULT_REDIRECT


def passkeys_module():
    if not PASSKEYS_ENABLED:
        return None
    try:
        import passkeys
        passkeys.webauthn_api()
        return passkeys
    except Exception:
        return None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "gptadmin-cookie-auth/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        message = fmt % args
        if self.path.startswith("/invite"):
            message = message.replace(self.path, "/invite")
        print(
            "%s - - [%s] %s"
            % (self.client_address[0], self.log_date_time_string(), message),
            flush=True,
        )

    def current_user(self) -> str | None:
        cookies = parse_cookie(self.headers.get("Cookie", ""))
        username = check_token(cookies.get(COOKIE_NAME, ""))
        if not username:
            return None
        try:
            account = access_control.get_user(ACCESS_DB, username)
        except Exception:
            return None
        return username if account and account["status"] == "active" else None

    def _security_headers(self, nonce: str | None = None) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if nonce:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; "
                f"script-src 'nonce-{nonce}'; "
                "style-src 'unsafe-inline'; connect-src 'self'; "
                "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            )

    def _send_json(self, status: int, value: dict[str, object], headers=()) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, header_value in headers:
            self.send_header(name, header_value)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, object] | None:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None
        if length < 1 or length > MAX_JSON_BODY:
            return None
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _require_passkey_write(self) -> bool:
        origin = self.headers.get("Origin", "")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        cookies = parse_cookie(self.headers.get("Cookie", ""))
        csrf_cookie_name = self.headers.get("X-CSRF-Cookie-Name", CSRF_COOKIE)
        csrf_cookie = (
            cookies.get(csrf_cookie_name, "")
            if valid_csrf_cookie_name(csrf_cookie_name)
            else ""
        )
        csrf_header = self.headers.get("X-CSRF-Token", "")
        if (
            origin != "https://auth.bezrabotnyi.com"
            or content_type != "application/json"
            or not csrf_cookie
            or not hmac.compare_digest(csrf_cookie, csrf_header)
        ):
            self._send_json(403, {"error": "request rejected"})
            return False
        return True

    def _send_html(
        self,
        body: str,
        *,
        csrf: str,
        nonce: str,
        csrf_cookie_name: str = CSRF_COOKIE,
        status: int = 200,
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self._security_headers(nonce)
        self.send_header(
            "Set-Cookie",
            f"{csrf_cookie_name}={csrf}; Path=/; Max-Age={CSRF_TTL}; Secure; HttpOnly; SameSite=Strict",
        )
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    @staticmethod
    def _clear_ceremony_cookie() -> tuple[str, str]:
        return (
            "Set-Cookie",
            f"{CEREMONY_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict",
        )

    def _ceremony_id(self) -> str:
        return parse_cookie(self.headers.get("Cookie", "")).get(CEREMONY_COOKIE, "")

    def _csrf_value(self) -> str:
        value = secrets.token_urlsafe(32)
        return value

    def _form_data(self):
        if self.headers.get("Origin", "") != "https://auth.bezrabotnyi.com":
            return None
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            return None
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None
        if length < 1 or length > MAX_JSON_BODY:
            return None
        try:
            data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            return None
        cookies = parse_cookie(self.headers.get("Cookie", ""))
        cookie_name = data.get("csrf_cookie_name", [""])[0]
        csrf_cookie = cookies.get(cookie_name, "") if valid_csrf_cookie_name(cookie_name) else ""
        csrf_form = data.get("csrf", [""])[0]
        if not csrf_cookie or not hmac.compare_digest(csrf_cookie, csrf_form):
            return None
        return data

    def _admin_user(self) -> str | None:
        if not ADMIN_ENABLED:
            return None
        user = self.current_user()
        try:
            return user if user and access_control.is_admin(ACCESS_DB, user) else None
        except Exception:
            return None

    def _admin_page(self, message: str = "", invite_url: str = "", status: int = 200) -> None:
        admin = self._admin_user()
        if not admin:
            user = self.current_user()
            if not user:
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/login?rd=" + urllib.parse.quote(
                    "https://auth.bezrabotnyi.com/admin", safe=""
                ))
                self.end_headers()
                return
            self.send_response(HTTPStatus.FORBIDDEN)
            self._security_headers()
            self.end_headers()
            return

        sites = access_control.list_sites(ACCESS_DB)
        users = access_control.list_users(ACCESS_DB)
        managed_users = [account for account in users if not account["is_admin"]]
        active_count = sum(account["status"] == "active" for account in managed_users)
        pending_count = sum(account["status"] == "pending" for account in managed_users)
        nonce, csrf_name, csrf = secrets.token_urlsafe(18), csrf_cookie_name_for_page(), self._csrf_value()

        def site_picker(selected_sites: set[str] | None = None) -> str:
            selected = selected_sites or set()
            items = "".join(
                '<label class="site-option" data-site-option data-site-name="'
                + html.escape(site.lower(), quote=True)
                + '"><input type="checkbox" name="sites" value="'
                + html.escape(site, quote=True)
                + ('" checked>' if site in selected else '">')
                + '<span class="site-check" aria-hidden="true"></span><span class="site-copy"><strong>'
                + html.escape(site)
                + '</strong><small>Доступ через SSO</small></span></label>'
                for site in sites
            )
            return (
                '<div class="site-picker" data-site-picker>'
                '<div class="site-picker-head">'
                '<label class="search-field"><span class="sr-only">Найти сайт</span>'
                '<input type="search" data-site-search placeholder="Найти сайт по адресу" autocomplete="off"></label>'
                '<div class="picker-actions"><span data-selected-count>'
                + str(len(selected))
                + ' выбрано</span><button class="text-button" type="button" data-site-all>Выбрать все</button>'
                '<button class="text-button muted" type="button" data-site-clear>Очистить</button></div></div>'
                '<div class="site-grid" data-site-list>'
                + items
                + '</div><p class="field-hint">Неотмеченные сайты для пользователя закрыты.</p></div>'
            )

        cards = []
        for account in users:
            raw_name = account["display_name"] or account["username"]
            name = html.escape(raw_name)
            login = html.escape(account["username"], quote=True)
            initial = html.escape(raw_name[:1].upper())
            if account["is_admin"]:
                cards.append(
                    '<article class="account-card owner-card" data-account-card data-account-search="'
                    + html.escape((raw_name + " " + account["username"]).lower(), quote=True)
                    + '"><div class="account-identity"><span class="avatar owner-avatar">'
                    + initial
                    + '</span><div><h3>'
                    + name
                    + '</h3><p>@'
                    + login
                    + '</p></div><span class="status-badge admin-badge">Суперадминистратор</span></div>'
                    '<div class="owner-note"><span class="owner-check">✓</span><span><strong>Полный доступ</strong>'
                    '<small>Все сайты SSO и настройки доступа</small></span></div></article>'
                )
                continue

            selected = set(account["sites"])
            status_values = (
                (("pending", "Ожидает установки пароля"), ("disabled", "Отключён"))
                if account["status"] == "pending"
                else (("active", "Активен"), ("disabled", "Отключён"))
            )
            status_options = "".join(
                '<option value="' + key + '"'
                + (" selected" if account["status"] == key else "")
                + ">"
                + label
                + "</option>"
                for key, label in status_values
            )
            status_labels = {
                "pending": ("Ожидает настройки", "pending-badge"),
                "active": ("Активен", "active-badge"),
                "disabled": ("Отключён", "disabled-badge"),
            }
            badge_text, badge_class = status_labels.get(account["status"], ("Неизвестно", "disabled-badge"))
            cards.append(
                '<article class="account-card" data-account-card data-account-search="'
                + html.escape((raw_name + " " + account["username"]).lower(), quote=True)
                + '"><div class="account-identity"><span class="avatar">'
                + initial
                + '</span><div class="account-title"><h3>'
                + name
                + '</h3><p>@'
                + login
                + '</p></div><span class="status-badge '
                + badge_class
                + '">'
                + badge_text
                + '</span></div><div class="account-summary"><span class="grant-dot"></span><span>'
                + str(len(selected))
                + " из "
                + str(len(sites))
                + ' сайтов доступно</span><details class="access-details"><summary>Настроить доступ</summary>'
                '<form method="post" action="/admin" class="access-form">'
                '<input type="hidden" name="csrf" value="__CSRF__"><input type="hidden" name="csrf_cookie_name" value="__CSRF_NAME__">'
                '<input type="hidden" name="action" value="update"><input type="hidden" name="username" value="'
                + login
                + '"><label class="status-field"><span>Состояние учётной записи</span><select name="status">'
                + status_options
                + '</select></label><fieldset class="site-fieldset"><legend>Разрешённые сайты</legend>'
                + site_picker(selected)
                + '</fieldset><div class="form-footer"><span class="field-hint">Изменения применяются сразу после сохранения.</span>'
                '<button class="primary-button" type="submit">Сохранить изменения</button></div></form></details></div></article>'
            )

        notice_class = "error-notice" if status >= 400 else "success-notice"
        message_html = (
            '<div class="notice ' + notice_class + '" role="status" aria-live="polite"><span class="notice-icon">✓</span><p>'
            + html.escape(message)
            + "</p></div>"
            if message
            else ""
        )
        invite_html = ""
        if invite_url:
            invite_html = (
                '<section class="invite-card" aria-labelledby="invite-title"><div class="invite-icon">↗</div>'
                '<div class="invite-copy"><p class="eyebrow">Доступ подготовлен</p><h2 id="invite-title">Ссылка для установки пароля</h2>'
                '<p>Передайте её пользователю. Ссылка действует 24 часа и сработает один раз.</p>'
                '<div class="invite-link-row"><input id="invite-link" readonly aria-label="Одноразовая ссылка" value="'
                + html.escape(invite_url, quote=True)
                + '"><button id="copy-link" class="primary-button" type="button">Скопировать ссылку</button></div></div></section>'
            )

        page = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Пользователи и доступ · SSO</title>
<style>
:root{color-scheme:light;--ink:#172033;--muted:#788397;--line:#e7eaf1;--paper:#fff;--canvas:#f4f6fa;--nav:#121a2b;--accent:#5757e8;--accent-dark:#4141cf;--accent-soft:#efefff;--green:#1b8b64;--green-soft:#e9f7f0;--amber:#ad6b13;--amber-soft:#fff5df;--red:#b74a54;--red-soft:#fff0f1;--shadow:0 18px 45px rgba(22,34,55,.07)}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--canvas);color:var(--ink);font:15px/1.5 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button{cursor:pointer}
a{color:inherit;text-decoration:none}
.layout{min-height:100vh}
.sidebar{position:fixed;inset:0 auto 0 0;width:252px;padding:28px 18px;background:var(--nav);color:#eef1fb;display:flex;flex-direction:column;z-index:2}
.brand{display:flex;align-items:center;gap:12px;padding:2px 10px 32px}
.brand-mark{width:36px;height:36px;border-radius:12px;background:linear-gradient(145deg,#7776ff,#5553e8);display:grid;place-items:center;color:white;font-weight:800;box-shadow:0 8px 22px #4f4bd955}
.brand-name{font-weight:750;font-size:15px;letter-spacing:.01em}
.brand-caption{display:block;color:#8d98ad;font-size:11px;margin-top:1px}
.nav-label{padding:0 12px 8px;color:#737f96;text-transform:uppercase;letter-spacing:.12em;font-size:10px;font-weight:750}
.side-nav{display:grid;gap:5px}
.side-nav a{padding:11px 12px;border-radius:10px;color:#aeb8cb;display:flex;align-items:center;gap:11px;font-size:13px;font-weight:600}
.side-nav a:hover,.side-nav a.active{color:white;background:#252f43}
.nav-icon{width:20px;text-align:center;color:#aaa9ff;font-size:16px}
.sidebar-bottom{margin-top:auto;padding:16px 10px 4px;border-top:1px solid #293347}
.admin-mini{display:flex;align-items:center;gap:10px}
.admin-mini .avatar{width:34px;height:34px;background:#293451;color:#c8c7ff}
.admin-mini strong{display:block;font-size:12px}
.admin-mini small{display:block;color:#8d98ad;font-size:11px}
.logout{display:inline-block;margin:14px 0 0 44px;font-size:12px;color:#aab4c7}
.logout:hover{color:white}
.main{margin-left:252px;max-width:1480px;padding:36px clamp(24px,4vw,64px) 72px}
.topline{display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;color:var(--muted);font-size:12px}
.breadcrumb{display:flex;align-items:center;gap:9px}
 .breadcrumb strong{color:#333d51;font-weight:650}
.top-actions{display:flex;align-items:center;gap:14px}.top-logout{color:#7d879a;font-size:11px;font-weight:650}.top-logout:hover{color:#343e53}
.secure-pill{display:flex;align-items:center;gap:7px;border:1px solid #dcefe6;background:#f0fbf5;color:#247a5b;border-radius:999px;padding:6px 11px;font-size:11px;font-weight:700}
.secure-dot{width:7px;height:7px;background:#32a878;border-radius:50%;box-shadow:0 0 0 3px #32a87820}
.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;margin-bottom:28px}
.eyebrow{margin:0 0 8px;color:var(--accent);font-size:10px;letter-spacing:.14em;text-transform:uppercase;font-weight:800}
h1{margin:0;font-size:clamp(28px,3.3vw,38px);line-height:1.12;letter-spacing:-.045em;font-weight:760}
.hero-copy{max-width:570px;margin:11px 0 0;color:var(--muted);font-size:14px}
.hero-policy{min-width:220px;padding:14px 17px;border:1px solid #dfe4ee;border-radius:14px;background:#fff}
.hero-policy strong{display:block;font-size:12px}
.hero-policy span{display:block;margin-top:4px;color:var(--muted);font-size:11px}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin-bottom:24px}
.stat-card{padding:17px 19px;border:1px solid var(--line);border-radius:15px;background:var(--paper);box-shadow:0 4px 14px #17203305}
.stat-top{display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:11px;font-weight:650}
.stat-icon{display:grid;place-items:center;width:29px;height:29px;border-radius:9px;background:var(--accent-soft);color:var(--accent);font-weight:800}
.stat-value{display:block;margin-top:10px;font-size:27px;line-height:1;font-weight:760;letter-spacing:-.04em}
.stat-caption{display:block;margin-top:7px;color:#9aa3b3;font-size:10px}
.content-grid{display:grid;grid-template-columns:minmax(280px,.82fr) minmax(0,1.45fr);gap:20px;align-items:start}
.panel{border:1px solid var(--line);border-radius:18px;background:var(--paper);box-shadow:var(--shadow)}
.panel-heading{padding:22px 23px 16px;border-bottom:1px solid #eef0f5}
.panel-heading h2{margin:0;font-size:16px;letter-spacing:-.02em}
.panel-heading p{margin:5px 0 0;color:var(--muted);font-size:12px}
.create-panel{position:sticky;top:20px}
.create-form{padding:20px 23px 23px}
.form-fields{display:grid;gap:15px}
.text-field,.status-field{display:grid;gap:6px}
.text-field>span,.status-field>span,.search-field>span{font-size:11px;font-weight:700;color:#505b70}
.text-field input,.search-field input,.status-field select,.invite-link-row input{width:100%;min-height:42px;border:1px solid #dce1eb;border-radius:10px;background:#fff;padding:9px 12px;color:var(--ink);outline:none;transition:border .15s,box-shadow .15s}
input::placeholder{color:#a6adba}
.text-field input:focus,.search-field input:focus,.status-field select:focus,.invite-link-row input:focus{border-color:#7878f0;box-shadow:0 0 0 3px #5757e81a}
.fieldset-label{display:flex;justify-content:space-between;align-items:baseline;margin:0 0 8px}
 .site-fieldset>legend{padding:0;font-size:12px;font-weight:750}
.fieldset-label small{color:var(--muted);font-size:10px}
.site-fieldset{margin:17px 0 0;padding:14px 0 0;border:0;border-top:1px solid #eef0f5}
.site-picker-head{display:grid;gap:9px;margin-bottom:9px}
.search-field{display:block}
.search-field input{min-height:38px;font-size:12px}
.picker-actions{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:10px}
.picker-actions [data-selected-count]{margin-right:auto;color:#536078;font-weight:700}
.text-button{padding:4px 0;border:0;background:none;color:var(--accent);font-size:10px;font-weight:700}
.text-button:hover{text-decoration:underline}
.text-button.muted{color:#8490a3}
.site-grid{display:grid;grid-template-columns:1fr;gap:5px;max-height:245px;overflow:auto;padding:2px 4px 2px 1px;scrollbar-color:#d5d9e4 transparent;scrollbar-width:thin}
.site-option{display:flex;align-items:center;gap:9px;min-width:0;padding:8px 9px;border:1px solid transparent;border-radius:10px;background:#f8f9fc;cursor:pointer;transition:background .15s,border .15s}
.site-option:hover{background:#f1f2ff;border-color:#e4e3ff}
.site-option:has(input:checked){background:#f2f1ff;border-color:#dedcff}
.site-option input{position:absolute;opacity:0;width:1px;height:1px}
.site-check{flex:0 0 16px;width:16px;height:16px;border:1px solid #ccd2df;border-radius:5px;background:#fff}
.site-option input:checked+.site-check{background:var(--accent);border-color:var(--accent);box-shadow:inset 0 0 0 3px white}
.site-option:focus-within{outline:3px solid #5757e829}
.site-copy{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;min-width:0}
.site-copy strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;font-weight:650}
.site-copy small{flex:none;color:#9aa3b3;font-size:9px}
.field-hint{margin:8px 0 0;color:#919bad;font-size:10px}
.primary-button{min-height:40px;padding:9px 14px;border:1px solid var(--accent);border-radius:10px;background:var(--accent);color:#fff;font-size:11px;font-weight:750;box-shadow:0 5px 12px #5757e824;transition:background .15s,transform .15s}
.primary-button:hover{background:var(--accent-dark);transform:translateY(-1px)}
.primary-button:focus-visible,.text-button:focus-visible,.side-nav a:focus-visible,summary:focus-visible{outline:3px solid #7776ff55;outline-offset:2px}
.create-submit{width:100%;margin-top:17px}
.directory-panel{min-width:0}
.directory-toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:15px 21px;border-bottom:1px solid #eef0f5}
.directory-toolbar .search-field{flex:1;max-width:310px}
.directory-toolbar .search-field input{min-height:36px}
.directory-count{color:var(--muted);font-size:10px;white-space:nowrap}
.account-list{display:grid;gap:10px;padding:14px}
.account-card{padding:15px 16px;border:1px solid var(--line);border-radius:14px;background:#fff;transition:border .15s,box-shadow .15s}
.account-card:hover{border-color:#d4d7e7;box-shadow:0 8px 20px #17203308}
.account-identity{display:flex;align-items:center;gap:11px;min-width:0}
.avatar{flex:none;width:38px;height:38px;display:grid;place-items:center;border-radius:12px;background:#e9edff;color:#4b4bd3;font-size:14px;font-weight:800}
.owner-avatar{background:#27334d;color:#c7c6ff}
.account-title{min-width:0;flex:1}
.account-identity h3{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin:0;font-size:13px;font-weight:750}
.account-identity p{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin:2px 0 0;color:var(--muted);font-size:10px}
.status-badge{flex:none;border-radius:999px;padding:5px 8px;font-size:9px;font-weight:750}
.admin-badge{background:#f0efff;color:#5851c9}
.active-badge{background:var(--green-soft);color:#247b5f}
.pending-badge{background:var(--amber-soft);color:#9b6417}
.disabled-badge{background:var(--red-soft);color:#a3454d}
.owner-note{display:flex;align-items:center;gap:10px;margin:13px 0 0 49px;padding:10px 12px;border-radius:10px;background:#f7f8fc}
.owner-check{width:21px;height:21px;border-radius:7px;display:grid;place-items:center;background:#e3f4ed;color:#278363;font-size:12px}
.owner-note strong,.owner-note small{display:block}
.owner-note strong{font-size:10px}
.owner-note small{margin-top:2px;color:var(--muted);font-size:9px}
.account-summary{margin:11px 0 0 49px;color:#68758a;font-size:10px}
.grant-dot{display:inline-block;width:7px;height:7px;margin-right:6px;border-radius:50%;background:#7c79ed}
.access-details{margin-top:12px;border-top:1px solid #f0f1f5}
.access-details summary{padding:11px 0 0;list-style:none;color:var(--accent);font-weight:750;font-size:10px;cursor:pointer}
.access-details summary::-webkit-details-marker{display:none}
.access-details summary:after{content:"＋";float:right;color:#8688d8;font-size:13px;line-height:1}
.access-details[open] summary:after{content:"−"}
.access-form{padding-top:14px}
.status-field{max-width:250px}
.status-field select{min-height:38px;font-size:11px}
.access-form .site-grid{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));max-height:300px}
.form-footer{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:13px}
.form-footer .field-hint{max-width:210px;margin:0}
.empty-state{padding:38px 16px;text-align:center;color:var(--muted);font-size:12px}
.empty-state strong{display:block;margin-bottom:5px;color:#39445a;font-size:13px}
.notice{display:flex;align-items:center;gap:10px;margin:0 0 20px;padding:13px 16px;border:1px solid #cfecdd;border-radius:13px;background:#f0fbf5;color:#226b50}
.notice p{margin:0;font-size:12px;font-weight:650}
 .notice-icon{width:24px;height:24px;display:grid;place-items:center;border-radius:8px;background:#d9f2e4;color:#1c805b}
.error-notice{border-color:#f3d1d4;background:#fff4f4;color:#9e3d49}.error-notice .notice-icon{background:#ffe0e2;color:#a6404c}
.invite-card{display:flex;gap:17px;margin:0 0 22px;padding:21px;border:1px solid #dad9ff;border-radius:16px;background:linear-gradient(120deg,#f5f4ff,#fff 65%);box-shadow:0 12px 30px #514ddd0d}
.invite-icon{flex:none;width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:#e6e4ff;color:#5553d7;font-size:20px}
.invite-copy{min-width:0;flex:1}
.invite-copy h2{margin:0;font-size:15px}
.invite-copy>p:not(.eyebrow){margin:5px 0 12px;color:var(--muted);font-size:11px}
.invite-link-row{display:flex;gap:8px}
.invite-link-row input{min-width:0;font-size:10px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
[hidden]{display:none!important}
@media(max-width:1120px){.content-grid{grid-template-columns:minmax(270px,.8fr) minmax(0,1.2fr)}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.site-copy small{display:none}}
@media(max-width:820px){.sidebar{position:static;width:auto;padding:12px 18px;display:block}.brand{padding:0}.brand-caption,.nav-label,.sidebar-bottom{display:none}.side-nav{display:flex;gap:4px;margin-top:13px;overflow:auto}.side-nav a{padding:8px 10px;font-size:11px;white-space:nowrap}.nav-icon{display:none}.main{margin:0;padding:24px 18px 48px}.topline{margin-bottom:23px}.hero{align-items:flex-start}.hero-policy{display:none}.create-panel{position:static}.content-grid{grid-template-columns:1fr}}
@media(max-width:520px){.topline{align-items:flex-start}.secure-pill{font-size:0;padding:8px}.secure-dot{width:8px;height:8px}.hero{margin-bottom:20px}h1{font-size:29px}.hero-copy{font-size:12px}.stats{gap:8px}.stat-card{padding:13px}.stat-value{font-size:23px}.stat-caption{font-size:9px}.panel-heading{padding:18px}.create-form{padding:17px 18px 19px}.directory-toolbar{padding:12px;flex-wrap:wrap}.directory-toolbar .search-field{max-width:none;flex-basis:100%}.account-list{padding:10px}.account-card{padding:13px}.status-badge{font-size:8px;padding:5px 7px}.account-summary,.owner-note{margin-left:0}.form-footer{align-items:flex-start;flex-direction:column}.form-footer .primary-button{width:100%}.invite-card{padding:16px;gap:11px}.invite-icon{width:34px;height:34px}.invite-link-row{flex-direction:column}.invite-link-row .primary-button{width:100%}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important}}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
  <div class="brand"><span class="brand-mark">A</span><span><span class="brand-name">Access Console</span><span class="brand-caption">единая точка управления</span></span></div>
  <p class="nav-label">Рабочая область</p>
  <nav class="side-nav" aria-label="Разделы панели">
    <a class="active" href="#overview"><span class="nav-icon">◈</span>Обзор</a>
    <a href="#new-user"><span class="nav-icon">＋</span>Новый пользователь</a>
    <a href="#accounts"><span class="nav-icon">♙</span>Пользователи</a>
  </nav>
  <div class="sidebar-bottom">
    <div class="admin-mini"><span class="avatar">__ADMIN_INITIAL__</span><span><strong>__ADMIN_NAME__</strong><small>Суперадминистратор</small></span></div>
    <a class="logout" href="/logout?rd=https%3A%2F%2Fauth.bezrabotnyi.com%2Flogin">Выйти из панели</a>
  </div>
</aside>
<main class="main" id="overview">
  <div class="topline"><div class="breadcrumb"><span>Управление</span><span aria-hidden="true">/</span><strong>Доступ SSO</strong></div><div class="top-actions"><span class="secure-pill"><span class="secure-dot"></span>Защищённая сессия</span><a class="top-logout" href="/logout?rd=https%3A%2F%2Fauth.bezrabotnyi.com%2Flogin">Выйти</a></div></div>
  <section class="hero"><div><p class="eyebrow">Администрирование SSO</p><h1>Пользователи и доступ</h1><p class="hero-copy">Создавайте учётные записи и решайте, к каким сайтам компании у них будет доступ.</p></div><div class="hero-policy"><strong>🔒 Доступ закрыт по умолчанию</strong><span>Каждое разрешение проверяется при входе на сайт.</span></div></section>
  <section class="stats" aria-label="Сводка доступа">
    <article class="stat-card"><div class="stat-top"><span>Пользователи</span><span class="stat-icon">♙</span></div><strong class="stat-value">__USER_COUNT__</strong><small class="stat-caption">обычные учётные записи</small></article>
    <article class="stat-card"><div class="stat-top"><span>Активны</span><span class="stat-icon">✓</span></div><strong class="stat-value">__ACTIVE_COUNT__</strong><small class="stat-caption">могут войти в систему</small></article>
    <article class="stat-card"><div class="stat-top"><span>Ожидают настройки</span><span class="stat-icon">…</span></div><strong class="stat-value">__PENDING_COUNT__</strong><small class="stat-caption">ещё не установили пароль</small></article>
    <article class="stat-card"><div class="stat-top"><span>Сайты SSO</span><span class="stat-icon">◎</span></div><strong class="stat-value">__SITE_COUNT__</strong><small class="stat-caption">доступны для назначения</small></article>
  </section>
  __MESSAGE__
  __INVITE__
  <div class="content-grid">
    <section class="panel create-panel" id="new-user">
      <div class="panel-heading"><p class="eyebrow">Приглашение</p><h2>Добавить пользователя</h2><p>Пользователь сам задаст пароль по защищённой ссылке.</p></div>
      <form method="post" action="/admin" class="create-form">
        <input type="hidden" name="csrf" value="__CSRF__"><input type="hidden" name="csrf_cookie_name" value="__CSRF_NAME__"><input type="hidden" name="action" value="create">
        <div class="form-fields"><label class="text-field"><span>Логин</span><input name="username" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9._-]*" autocomplete="off" placeholder="например, oleg.petrov"></label>
        <label class="text-field"><span>Имя пользователя</span><input name="display_name" required maxlength="100" placeholder="Олег Петров"></label></div>
        <fieldset class="site-fieldset"><legend>Разрешённые сайты</legend><div class="fieldset-label"><small>Можно выбрать несколько</small></div>__OPTIONS__</fieldset>
        <button class="primary-button create-submit" type="submit">Создать и получить ссылку</button>
      </form>
    </section>
    <section class="panel directory-panel" id="accounts">
      <div class="panel-heading"><p class="eyebrow">Каталог доступа</p><h2>Учётные записи</h2><p>Состояние пользователей и назначенные сайты.</p></div>
      <div class="directory-toolbar"><label class="search-field"><span class="sr-only">Найти пользователя</span><input type="search" id="user-search" placeholder="Найти по имени или логину" autocomplete="off"></label><span class="directory-count"><strong>__USER_COUNT__</strong> пользователей</span></div>
      <div class="account-list" id="account-list">__CARDS__<div class="empty-state" id="empty-state" hidden><strong>Ничего не найдено</strong>Измените запрос или очистите поиск.</div></div>
    </section>
  </div>
</main>
</div>
<script nonce="__NONCE__">
for(const picker of document.querySelectorAll("[data-site-picker]")){
  const search=picker.querySelector("[data-site-search]");
  const items=[...picker.querySelectorAll("[data-site-option]")];
  const count=picker.querySelector("[data-selected-count]");
  const update=()=>{
    const term=(search.value||"").trim().toLocaleLowerCase();
    for(const item of items)item.hidden=!item.dataset.siteName.includes(term);
    count.textContent=picker.querySelectorAll("input[name=sites]:checked").length+" выбрано";
  };
  search.addEventListener("input",update);
  picker.querySelector("[data-site-all]").addEventListener("click",()=>{for(const item of items)item.querySelector("input").checked=true;update()});
  picker.querySelector("[data-site-clear]").addEventListener("click",()=>{for(const item of items)item.querySelector("input").checked=false;update()});
  picker.addEventListener("change",update);
}
const userSearch=document.getElementById("user-search");
const accounts=[...document.querySelectorAll("[data-account-card]")];
const emptyState=document.getElementById("empty-state");
const updateAccounts=()=>{
  const term=(userSearch.value||"").trim().toLocaleLowerCase();
  let visible=0;
  for(const account of accounts){const show=account.dataset.accountSearch.includes(term);account.hidden=!show;if(show)visible++}
  emptyState.hidden=visible>0;
};
userSearch.addEventListener("input",updateAccounts);
const copyButton=document.getElementById("copy-link");
if(copyButton)copyButton.addEventListener("click",async()=>{
  const input=document.getElementById("invite-link");
  try{await navigator.clipboard.writeText(input.value);copyButton.textContent="Ссылка скопирована"}
  catch(error){input.focus();input.select();document.execCommand("copy");copyButton.textContent="Ссылка скопирована"}
});
</script>
</body>
</html>"""
        page = (
            page.replace("__ADMIN_INITIAL__", html.escape(admin[:1].upper()))
            .replace("__ADMIN_NAME__", html.escape(admin))
            .replace("__USER_COUNT__", str(len(managed_users)))
            .replace("__ACTIVE_COUNT__", str(active_count))
            .replace("__PENDING_COUNT__", str(pending_count))
            .replace("__SITE_COUNT__", str(len(sites)))
            .replace("__MESSAGE__", message_html)
            .replace("__INVITE__", invite_html)
            .replace("__CSRF__", csrf)
            .replace("__CSRF_NAME__", csrf_name)
            .replace("__NONCE__", nonce)
            .replace("__OPTIONS__", site_picker())
            .replace("__CARDS__", "".join(cards) or '<div class="empty-state"><strong>Пока нет пользователей</strong>Создайте первую учётную запись в форме слева.</div>')
        )
        self._send_html(page, csrf=csrf, nonce=nonce, csrf_cookie_name=csrf_name, status=status)

    def _invite_page(
        self, message: str = "", success: bool = False, status: int = 200, token: str = ""
    ) -> None:
        csrf, csrf_name, nonce = self._csrf_value(), csrf_cookie_name_for_page(), secrets.token_urlsafe(18)
        if not INVITE_SETUP_ENABLED and not success:
            body = (
                '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="referrer" content="no-referrer">'
                '<meta name="viewport" content="width=device-width,initial-scale=1"><title>SSO</title><main>'
                '<h1>Установка пароля временно недоступна</h1><p>Откройте ссылку на основном SSO.</p></main>'
                f'<script nonce="{nonce}">history.replaceState(null,"",location.pathname)</script></html>'
            )
            self._send_html(body, csrf=csrf, nonce=nonce, csrf_cookie_name=csrf_name, status=503)
            return
        try:
            invite = access_control.invite_info(ACCESS_DB, token) if token else None
        except Exception:
            invite = None
        if success:
            content = '<p>Пароль установлен. Теперь можно войти.</p><a href="/login">Перейти ко входу</a>'
        elif invite or not token:
            token_value = html.escape(token, quote=True)
            content = (
                '<form id="invite-form" method="post" action="/invite">'
                f'<input id="invite-token" type="hidden" name="token" value="{token_value}">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<input type="hidden" name="csrf_cookie_name" value="{csrf_name}">'
                '<label>Пароль (не менее 12 символов)<br><input name="password" type="password" minlength="12" maxlength="1024" required autocomplete="new-password"></label><br><br>'
                '<label>Повторите пароль<br><input name="password_confirm" type="password" minlength="12" maxlength="1024" required autocomplete="new-password"></label><br><br>'
                '<button>Установить пароль</button></form>'
            )
        else:
            content = '<a href="/login">Перейти ко входу</a>'
            status = max(status, HTTPStatus.GONE)
        script = (
            '<script nonce="' + nonce + '">const t=new URLSearchParams(location.hash.slice(1)).get("token");'
            'history.replaceState(null,"",location.pathname);const f=document.getElementById("invite-form");'
            'if(f&&t)document.getElementById("invite-token").value=t;else if(f){f.hidden=true;'
            'const e=document.createElement("p");e.textContent="В ссылке нет кода приглашения.";f.before(e);}</script>'
            if not token else ""
        )
        body = (
            '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Установка пароля SSO</title><style>body{font:16px system-ui;background:#f2f5f8;color:#17202a;margin:0}'
            'main{max-width:540px;margin:50px auto;padding:28px;background:white;border:1px solid #dce2e9;border-radius:14px}'
            'input{font:inherit;padding:10px;border:1px solid #aeb9c6;border-radius:8px;width:95%}button{font:inherit;padding:10px 16px;border:0;border-radius:8px;background:#1959a6;color:white}</style></head><body><main>'
            '<h1>Задайте пароль</h1>'
            + (f'<p>{html.escape(message)}</p>' if message else "")
            + content + script + '</main></body></html>'
        )
        self._send_html(body, csrf=csrf, nonce=nonce, csrf_cookie_name=csrf_name, status=status)

    def _login_page(self, redirect: str, error: bool = False) -> None:
        csrf = self._csrf_value()
        csrf_cookie_name = csrf_cookie_name_for_page()
        nonce = secrets.token_urlsafe(18)
        enabled = passkeys_module() is not None
        user = html.escape(self.current_user() or "roomhacker", quote=True)
        redirect_json = (
            json.dumps(redirect).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        )
        error_html = '<p class="err">Неверный логин или пароль</p>' if error else ""
        intro = "Войдите с ключом доступа или паролем." if enabled else "Войдите с паролем."
        passkey_html = (
            '<button type="button" class="passkey-login" id="passkey-login">'
            '<svg aria-hidden="true" viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/>'
            '<path d="M8 10V7a4 4 0 0 1 8 0v1"/></svg> Войти с ключом</button>'
            if enabled else ""
        )
        passkey_link = '<div class="access-link"><a href="/passkeys">Добавить ключ входа</a></div>' if enabled else ""
        passkey_script = (
            """
async function loginWithPasskey(){
  const button=document.getElementById('passkey-login');
  const status=document.getElementById('passkey-status');
  button.disabled=true;status.textContent='Ожидаю подтверждение…';
  try{
    const start=await fetch('/passkey/auth/options',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF,'X-CSRF-Cookie-Name':CSRF_COOKIE_NAME},body:'{}'});
    if(!start.ok)throw new Error('Вход по ключу сейчас недоступен');
    const options=await start.json();
    options.challenge=fromB64url(options.challenge);
    if(options.allowCredentials)for(const c of options.allowCredentials)c.id=fromB64url(c.id);
    const credential=await navigator.credentials.get({publicKey:options});
    if(!credential)throw new Error('Вход отменён');
    const result=await fetch('/passkey/auth/verify',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF,'X-CSRF-Cookie-Name':CSRF_COOKIE_NAME},
      body:JSON.stringify({credential:credentialToJSON(credential)})});
    if(!result.ok)throw new Error('Не удалось войти по ключу');
    location.href=redirectWithLoginFragment(REDIRECT);
  }catch(e){status.textContent=e.message||'Не удалось войти по ключу';button.disabled=false;}
}
""" if enabled else ""
        )
        page = f'''<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>bezrabotnyi.com — Вход</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;background:#111;color:#eee;display:grid;place-items:center;min-height:100vh;margin:0;padding:20px}}
.card{{background:#1b1b1b;padding:30px;border:1px solid #383838;border-radius:16px;width:min(560px,100%);box-shadow:0 10px 40px #0008}}
h1{{font-size:28px;line-height:1.2;margin:0 0 8px}}.intro{{color:#aaa;margin:0 0 24px}}
label{{display:block;color:#aaa;font-size:14px;margin:12px 0 6px}}
input{{width:100%;min-width:0;padding:12px;border-radius:10px;border:1px solid #494949;background:#111;color:#fff;font:inherit}}
input:focus{{outline:2px solid #7da6ff;outline-offset:1px}}
button{{font:inherit;color:#eee;cursor:pointer}}button:disabled{{opacity:.6;cursor:wait}}
.passkey-login{{width:100%;display:flex;align-items:center;justify-content:center;gap:12px;margin:0 0 20px;padding:14px;border-radius:11px;border:1px solid #383838;background:#242424;font-size:18px;font-weight:600}}
.passkey-login:hover{{background:#2c2c2c}}.passkey-login svg{{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}}
.divider{{display:flex;align-items:center;gap:12px;color:#888;font-size:13px;margin:2px 0 14px}}
.divider:before,.divider:after{{content:\"\";height:1px;background:#383838;flex:1}}
.login-form{{padding:0;background:none;border:0;border-radius:0;width:auto;box-shadow:none}}
.password-row{{display:flex;gap:10px;align-items:center}}.password-row input{{flex:1}}
.password-submit{{width:58px;height:48px;flex:none;border:1px solid #493321;border-radius:10px;background:#2a1e16;color:#d39a69;font-size:22px}}
.password-submit:hover{{background:#36251b}}.access-link{{display:flex;justify-content:flex-end;margin:18px 0 0}}
a{{color:#aaa;text-decoration:none}}a:hover{{color:#ddd;text-decoration:underline}}
.status{{min-height:1.5em;color:#ff806f;margin:12px 0 0}}.status:empty{{display:none}}.hint,small{{color:#888}}small{{display:block;margin-top:18px}}
.err{{color:#ff806f;margin:0 0 12px}}
@media(max-width:480px){{.card{{padding:22px}}h1{{font-size:24px}}}}
</style></head><body><main class=\"card\"><h1>Войти в bezrabotnyi.com</h1>
<p class=\"intro\">{intro}</p>{error_html}
{passkey_html}
<p id=\"passkey-status\" class=\"status\" aria-live=\"polite\"></p>
<div class=\"divider\">или пароль</div>
<form class=\"login-form\" method=\"post\" action=\"/login\">
<label for=\"username\">Логин</label><input id=\"username\" name=\"username\" autocomplete=\"username\" value=\"{user}\">
<label for=\"password\">Пароль</label><div class=\"password-row\">
<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\">
<button class=\"password-submit\" type=\"submit\" aria-label=\"Войти паролем\" title=\"Войти паролем\">↵</button></div>
<p id=\"enrollment-status\" class=\"status\" aria-live=\"polite\"></p>
<input id=\"redirect-path\" type=\"hidden\" name=\"rd\" value=\"{html.escape(redirect, quote=True)}\">
<input type=\"hidden\" name=\"csrf\" value=\"{html.escape(csrf, quote=True)}\">
<input type=\"hidden\" name=\"csrf_cookie_name\" value=\"{html.escape(csrf_cookie_name, quote=True)}\">
</form>
{passkey_link}
<small>После входа вы останетесь авторизованы на сайтах *.bezrabotnyi.com.</small></main>
<script nonce=\"{nonce}\">
const CSRF={json.dumps(csrf)}, CSRF_COOKIE_NAME={json.dumps(csrf_cookie_name)}, REDIRECT={redirect_json};
{LOGIN_FRAGMENT_SCRIPT}
const loginForm=document.querySelector('.login-form');
if(loginForm)loginForm.addEventListener('submit',async e=>{{
  e.preventDefault();
  const password=document.getElementById('password'),submit=loginForm.querySelector('.password-submit');
  const status=document.getElementById('enrollment-status');
  if(!password.value){{status.textContent='Введите пароль.';password.focus();return;}}
  submit.disabled=true;
  try{{
    const response=await fetch(loginForm.action,{{method:'POST',credentials:'same-origin',
      headers:{{'Content-Type':'application/x-www-form-urlencoded','X-SSS-Login':'1'}},
      body:new URLSearchParams(new FormData(loginForm))}});
    const result=await response.json();
    if(!response.ok||!result.ok||typeof result.redirect!=='string'){{
      status.textContent=response.status===401?'Неверный логин или пароль.':'Не удалось выполнить вход. Обновите страницу.';
      return;
    }}
    location.assign(redirectWithLoginFragment(result.redirect));
  }}catch(e){{status.textContent='Не удалось выполнить вход. Проверьте соединение.';}}
  finally{{submit.disabled=false;}}
}});
function fromB64url(v){{const s=v.replace(/-/g,'+').replace(/_/g,'/');const b=atob(s+'='.repeat((4-s.length%4)%4));return Uint8Array.from(b,c=>c.charCodeAt(0));}}
function toB64url(v){{return btoa(String.fromCharCode(...new Uint8Array(v))).replace(/=/g,'').replace(/\\+/g,'-').replace(/\\//g,'_');}}
function credentialToJSON(c){{const r=c.response;return {{id:c.id,rawId:toB64url(c.rawId),type:c.type,
 response:{{clientDataJSON:toB64url(r.clientDataJSON),authenticatorData:toB64url(r.authenticatorData),
 signature:toB64url(r.signature),userHandle:r.userHandle?toB64url(r.userHandle):null}},
 clientExtensionResults:c.getClientExtensionResults(),authenticatorAttachment:c.authenticatorAttachment}};}}
function registrationToJSON(c){{const r=c.response;return {{id:c.id,rawId:toB64url(c.rawId),type:c.type,
 response:{{clientDataJSON:toB64url(r.clientDataJSON),attestationObject:toB64url(r.attestationObject),
 transports:r.getTransports?r.getTransports():[]}},clientExtensionResults:c.getClientExtensionResults(),
 authenticatorAttachment:c.authenticatorAttachment}};}}
function passkeyDeviceLabel(){{
 const platform=((navigator.userAgentData&&navigator.userAgentData.platform)||navigator.platform||'').toLowerCase();
 if(platform.includes('mac'))return 'Mac';
 if(platform.includes('ipad'))return 'iPad';
 if(platform.includes('iphone'))return 'iPhone';
 if(platform.includes('android'))return 'Android';
 if(platform.includes('win'))return 'Windows';
 if(platform.includes('linux'))return 'Linux';
 return 'Устройство';
}}
function passkeyLogicalCores(){{
 const value=navigator.hardwareConcurrency;
 return Number.isInteger(value)&&value>0&&value<=256?value:null;
}}
{passkey_script}
const pb=document.getElementById('passkey-login');if(pb)pb.addEventListener('click',loginWithPasskey);
let pendingRegistrationOptions=null;
const addLink=document.querySelector('.access-link a');if(addLink)addLink.addEventListener('click',async e=>{{
  e.preventDefault();const password=document.getElementById('password');
  if(!password.value){{document.getElementById('enrollment-status').textContent='Введите пароль, чтобы добавить ключ входа.';password.focus();return;}}
  const status=document.getElementById('enrollment-status'),username=document.getElementById('username');
  addLink.setAttribute('aria-disabled','true');
  try{{
    if(!pendingRegistrationOptions){{
      status.textContent='Проверяю пароль…';
      const startResponse=await fetch('/passkey/register/options',{{method:'POST',credentials:'same-origin',
        headers:{{'Content-Type':'application/json','X-CSRF-Token':CSRF,'X-CSRF-Cookie-Name':CSRF_COOKIE_NAME}},
        body:JSON.stringify({{username:username.value,password:password.value,label:passkeyDeviceLabel(),logical_cores:passkeyLogicalCores()}})}});
      if(startResponse.status===401){{status.textContent='Неверный пароль';return;}}
      if(!startResponse.ok)throw new Error('Не удалось начать регистрацию ключа');
      const start=await startResponse.json();
      start.options.challenge=fromB64url(start.options.challenge);
      start.options.user.id=fromB64url(start.options.user.id);
      for(const c of (start.options.excludeCredentials||[]))c.id=fromB64url(c.id);
      pendingRegistrationOptions=start.options;
      addLink.textContent='Продолжить с Touch ID';
      status.textContent='Пароль принят. Нажмите «Продолжить с Touch ID», затем подтвердите на устройстве.';
      return;
    }}
    const options=pendingRegistrationOptions;
    pendingRegistrationOptions=null;
    addLink.textContent='Добавить ключ входа';
    status.textContent='Подтвердите Touch ID или другой способ на этом устройстве…';
    // Invoke the WebAuthn API synchronously in this click handler. The server
    // options were prepared by the previous click so transient user activation
    // is not lost while waiting for network I/O.
    const createPromise=navigator.credentials.create({{publicKey:options}});
    const credential=await createPromise;
    if(!credential)throw new Error('Регистрация отменена');
    const finish=await fetch('/passkey/register/verify',{{method:'POST',credentials:'same-origin',
      headers:{{'Content-Type':'application/json','X-CSRF-Token':CSRF,'X-CSRF-Cookie-Name':CSRF_COOKIE_NAME}},
      body:JSON.stringify({{credential:registrationToJSON(credential)}})}});
    if(!finish.ok)throw new Error('Не удалось добавить ключ');
    password.value='';status.textContent='Ключ добавлен';location.assign(redirectWithLoginFragment(REDIRECT));
  }}catch(error){{
    if(error&&error.name==='NotAllowedError'){{
      pendingRegistrationOptions=null;addLink.textContent='Добавить ключ входа';
      status.textContent='Touch ID не подтвердил запрос или истёк таймаут. Нажмите «Добавить ключ входа», чтобы повторить.';
    }}else{{status.textContent=error.message||'Не удалось добавить ключ';}}
  }}
  finally{{addLink.removeAttribute('aria-disabled');}}
}});
</script></body></html>'''
        self._send_html(page, csrf=csrf, nonce=nonce, csrf_cookie_name=csrf_cookie_name)

    def _passkeys_page(self) -> None:
        user = self.current_user()
        if not user or user not in read_users():
            self.send_response(302)
            self._security_headers()
            self.send_header("Location", "/login?rd=%2Fpasskeys")
            self.end_headers()
            return
        module = passkeys_module()
        csrf = self._csrf_value()
        csrf_cookie_name = csrf_cookie_name_for_page()
        nonce = secrets.token_urlsafe(18)
        items = []
        if module:
            try:
                stored_hash = read_users().get(user)
                generation = module.account_generation(read_secret(), user, stored_hash or "")
                for key in module.list_credentials(user, generation):
                    key_id = base64.urlsafe_b64encode(key["credential_id"]).decode().rstrip("=")
                    created = time.strftime("%Y-%m-%d", time.localtime(key["created_at"]))
                    items.append(
                        f'<li>{html.escape(key["label"])} — {created} '
                        f'<details><summary>Сведения об устройстве</summary>'
                        f'<p>Логических ядер по данным браузера: {html.escape(str(key["logical_cores"]) if key["logical_cores"] is not None else "не сообщено")}</p>'
                        f'<p><code style="white-space:pre-wrap;overflow-wrap:anywhere">{html.escape(key["user_agent"] or "User-Agent не сохранён для этого ключа")}</code></p></details> '
                        f'<button type=\"button\" class=\"revoke\" data-id=\"{key_id}\">Удалить</button></li>'
                    )
            except Exception:
                    items = []
        feature = (
            '<p>Закрытые ключи остаются в authenticator. Добавление нового ключа доступно прямо на странице входа.</p>'
            '<ul id=\"keys\">' + ''.join(items) + '</ul>'
            '<section id=\"revoke-panel\" hidden><label>Пароль SSO для удаления ключа'
            '<input id=\"revoke-password\" type=\"password\" autocomplete=\"current-password\"></label>'
            '<button type=\"button\" id=\"confirm-revoke\">Удалить ключ</button>'
            '<button type=\"button\" id=\"cancel-revoke\">Отмена</button></section>'
            '<p>Для удаления ключа потребуется снова ввести пароль. Вход паролем останется доступен.</p>'
            if module else '<p>Вход по ключу сейчас отключён на этом узле.</p>'
        )
        script = (
            """
async function api(path,body){const r=await fetch(path,{method:'POST',credentials:'same-origin',
 headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF,'X-CSRF-Cookie-Name':CSRF_COOKIE_NAME},body:JSON.stringify(body)});
 if(!r.ok)throw new Error('Операция не выполнена');return r.json();}
let revokeCredentialId='';
function revokeKey(id){
 revokeCredentialId=id;
 const panel=document.getElementById('revoke-panel'),password=document.getElementById('revoke-password');
 panel.hidden=false;password.value='';password.focus();
}
function cancelRevoke(){
 revokeCredentialId='';document.getElementById('revoke-password').value='';
 document.getElementById('revoke-panel').hidden=true;
}
async function confirmRevoke(){
 const password=document.getElementById('revoke-password'),button=document.getElementById('confirm-revoke');
 if(!revokeCredentialId||!password.value){document.getElementById('status').textContent='Введите пароль SSO';return;}
 button.disabled=true;
 try{await api('/passkey/revoke',{credential_id:revokeCredentialId,password:password.value});location.reload();}
 catch(e){document.getElementById('status').textContent=e.message;}
 finally{password.value='';button.disabled=false;}
}
""" if module else ""
        )
        page = f'''<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Ключи входа</title>
<style>body{{font-family:system-ui,sans-serif;background:#111;color:#eee;max-width:520px;margin:3rem auto;padding:1rem}}
input,button{{display:block;box-sizing:border-box;width:100%;margin:.6rem 0;padding:.7rem;border-radius:8px;border:1px solid #444;background:#1b1b1b;color:#eee}}
button{{background:#2d6cdf;border:0;cursor:pointer}}li{{margin:.8rem 0}}a{{color:#9abaff}}</style></head><body>
<h1>Ключи входа</h1><p>Пользователь: {html.escape(user)}</p>{feature}
<p id=\"status\" aria-live=\"polite\"></p><a href=\"/login\">Вернуться ко входу</a>
<script nonce=\"{nonce}\">const CSRF={json.dumps(csrf)}, CSRF_COOKIE_NAME={json.dumps(csrf_cookie_name)};
{script}
document.querySelectorAll('button.revoke').forEach(b=>b.addEventListener('click',()=>revokeKey(b.dataset.id)));
const cancel=document.getElementById('cancel-revoke');if(cancel)cancel.addEventListener('click',cancelRevoke);
const confirm=document.getElementById('confirm-revoke');if(confirm)confirm.addEventListener('click',confirmRevoke);
</script></body></html>'''
        self._send_html(page, csrf=csrf, nonce=nonce, csrf_cookie_name=csrf_cookie_name)

    def _passkey_failure(self, status: int = 400, *, clear_ceremony: bool = False) -> None:
        headers = (self._clear_ceremony_cookie(),) if clear_ceremony else ()
        self._send_json(status, {"error": "passkey operation failed"}, headers)

    def _start_passkey_authentication(self, module, _data: dict[str, object]) -> None:
        api, *types = module.webauthn_api()
        user_verification = types[-1]
        transaction_id, challenge = module.create_challenge("authenticate", {})
        options = api.generate_authentication_options(
            rp_id=module.RP_ID,
            challenge=challenge,
            user_verification=user_verification.REQUIRED,
        )
        response = json.loads(api.options_to_json(options))
        cookie = (
            "Set-Cookie",
            f"{CEREMONY_COOKIE}={transaction_id}; Path=/; Max-Age={module.CHALLENGE_TTL_SECONDS}; "
            "Secure; HttpOnly; SameSite=Strict",
        )
        self._send_json(200, response, (cookie,))

    def _finish_passkey_authentication(self, module, data: dict[str, object]) -> None:
        state = module.consume_challenge(self._ceremony_id(), "authenticate")
        if not state:
            self._passkey_failure(clear_ceremony=True)
            return
        api, *_ = module.webauthn_api()
        credential = data.get("credential")
        if not isinstance(credential, dict) or not isinstance(credential.get("response"), dict):
            self._passkey_failure(clear_ceremony=True)
            return
        try:
            credential_id = api.base64url_to_bytes(str(credential.get("rawId", "")))
            stored = module.get_credential(credential_id)
            if not stored:
                self._passkey_failure(clear_ceremony=True)
                return
            users = read_users()
            password_hash = users.get(stored["username"])
            if not password_hash:
                self._passkey_failure(clear_ceremony=True)
                return
            generation = module.account_generation(read_secret(), stored["username"], password_hash)
            if not hmac.compare_digest(generation, stored["generation"]):
                self._passkey_failure(clear_ceremony=True)
                return
            response = credential["response"]
            user_handle = response.get("userHandle")
            if not isinstance(user_handle, str) or not hmac.compare_digest(
                api.base64url_to_bytes(user_handle), stored["user_handle"]
            ):
                self._passkey_failure(clear_ceremony=True)
                return
            verification = api.verify_authentication_response(
                credential=credential,
                expected_challenge=state["challenge"],
                expected_rp_id=module.RP_ID,
                expected_origin=module.ORIGIN,
                credential_public_key=stored["public_key"],
                credential_current_sign_count=stored["sign_count"],
                require_user_verification=True,
            )
            if verification.credential_id != stored["credential_id"]:
                self._passkey_failure(clear_ceremony=True)
                return
            latest_hash = read_users().get(stored["username"])
            if not latest_hash or not hmac.compare_digest(
                module.account_generation(read_secret(), stored["username"], latest_hash),
                stored["generation"],
            ):
                self._passkey_failure(clear_ceremony=True)
                return
            if not module.record_success(
                credential_id, stored["sign_count"], verification.new_sign_count
            ):
                self._passkey_failure(clear_ceremony=True)
                return
            token = make_token(stored["username"])
            self._send_json(
                200,
                {"ok": True},
                (
                    self._clear_ceremony_cookie(),
                    (
                        "Set-Cookie",
                        f"{COOKIE_NAME}={token}; Domain={COOKIE_DOMAIN}; Path=/; "
                        f"Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Lax",
                    ),
                ),
            )
        except Exception:
            # Never log assertion bytes or library exception detail.
            print("[auth] passkey authentication rejected", flush=True)
            self._passkey_failure(clear_ceremony=True)

    def _start_passkey_registration(self, module, data: dict[str, object]) -> None:
        session_username = self.current_user()
        requested_username = data.get("username")
        if session_username:
            username = session_username
            if requested_username is not None and (
                not isinstance(requested_username, str)
                or requested_username.strip() != session_username
            ):
                self._passkey_failure(401)
                return
        elif isinstance(requested_username, str):
            username = requested_username.strip()
        else:
            username = ""
        users = read_users()
        password = data.get("password")
        label = data.get("label", "Устройство")
        logical_cores = data.get("logical_cores")
        user_agent = self.headers.get("User-Agent", "")
        if logical_cores is not None and (
            type(logical_cores) is not int or logical_cores < 1 or logical_cores > 256
        ):
            self._passkey_failure(400)
            return
        if len(user_agent) > 4096:
            self._passkey_failure(400)
            return
        if (
            not username
            or username not in users
            or not isinstance(password, str)
            or not verify_password(username, password)
            or not isinstance(label, str)
        ):
            self._passkey_failure(401)
            return
        label = " ".join(label.split())[:48] or "Passkey"
        if logical_cores is not None:
            suffix = f" · {logical_cores} ядер"
            label = label[: max(1, 48 - len(suffix))] + suffix
        password_hash = users[username]
        generation = module.account_generation(read_secret(), username, password_hash)
        user_handle, excluded = module.principal_for_registration(username, generation)
        api, attestation, attachment, selection, descriptor, resident_key, verification = (
            module.webauthn_api()
        )
        challenge_id, challenge = module.create_challenge(
            "register",
            {
                "username": username,
                "generation": generation,
                "user_handle": user_handle,
                "label": label,
                "user_agent": user_agent,
                "logical_cores": logical_cores,
            },
        )
        options = api.generate_registration_options(
            rp_id=module.RP_ID,
            rp_name="bezrabotnyi.com",
            user_name=username,
            user_display_name=username,
            user_id=user_handle,
            challenge=challenge,
            attestation=attestation.NONE,
            authenticator_selection=selection(
                authenticator_attachment=attachment.PLATFORM,
                resident_key=resident_key.REQUIRED,
                user_verification=verification.REQUIRED,
            ),
            exclude_credentials=[descriptor(id=value) for value in excluded],
        )
        body = {"options": json.loads(api.options_to_json(options))}
        cookie = (
            "Set-Cookie",
            f"{CEREMONY_COOKIE}={challenge_id}; Path=/; Max-Age={module.CHALLENGE_TTL_SECONDS}; "
            "Secure; HttpOnly; SameSite=Strict",
        )
        response_headers = [cookie]
        if not session_username:
            session_token = make_token(username)
            response_headers.append((
                "Set-Cookie",
                f"{COOKIE_NAME}={session_token}; Domain={COOKIE_DOMAIN}; Path=/; "
                f"Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Lax",
            ))
        self._send_json(200, body, tuple(response_headers))

    def _finish_passkey_registration(self, module, data: dict[str, object]) -> None:
        state = module.consume_challenge(self._ceremony_id(), "register")
        username = self.current_user()
        if not state or username != state.get("username"):
            self._passkey_failure(clear_ceremony=True)
            return
        credential = data.get("credential")
        if not isinstance(credential, dict):
            self._passkey_failure(clear_ceremony=True)
            return
        try:
            password_hash = read_users().get(username)
            if not password_hash or not hmac.compare_digest(
                module.account_generation(read_secret(), username, password_hash),
                state["generation"],
            ):
                self._passkey_failure(clear_ceremony=True)
                return
            api, *_ = module.webauthn_api()
            verified = api.verify_registration_response(
                credential=credential,
                expected_challenge=state["challenge"],
                expected_rp_id=module.RP_ID,
                expected_origin=module.ORIGIN,
                require_user_verification=True,
            )
            if not verified.user_verified:
                self._passkey_failure(clear_ceremony=True)
                return
            latest_hash = read_users().get(username)
            if not latest_hash or not hmac.compare_digest(
                module.account_generation(read_secret(), username, latest_hash),
                state["generation"],
            ):
                self._passkey_failure(clear_ceremony=True)
                return
            saved = module.save_credential(
                credential_id=verified.credential_id,
                username=username,
                generation=state["generation"],
                user_handle=state["user_handle"],
                public_key=verified.credential_public_key,
                sign_count=verified.sign_count,
                label=state["label"],
                backed_up=verified.credential_backed_up,
                user_agent=state.get("user_agent", ""),
                logical_cores=state.get("logical_cores"),
            )
            if not saved:
                self._passkey_failure(clear_ceremony=True)
                return
            self._send_json(
                200, {"ok": True}, (self._clear_ceremony_cookie(),)
            )
        except Exception:
            print("[auth] passkey registration rejected", flush=True)
            self._passkey_failure(clear_ceremony=True)

    def _revoke_passkey(self, module, data: dict[str, object]) -> None:
        username = self.current_user()
        users = read_users()
        password = data.get("password")
        credential_text = data.get("credential_id")
        if (
            not username
            or username not in users
            or not isinstance(password, str)
            or not verify_password(username, password)
            or not isinstance(credential_text, str)
        ):
            self._passkey_failure(401)
            return
        try:
            api, *_ = module.webauthn_api()
            credential_id = api.base64url_to_bytes(credential_text)
            generation = module.account_generation(read_secret(), username, users[username])
            if not module.revoke_credential(username, generation, credential_id):
                self._passkey_failure(404)
                return
            self._send_json(200, {"ok": True})
        except Exception:
            print("[auth] passkey revocation rejected", flush=True)
            self._passkey_failure()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/healthz":
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.end_headers()
            return
        if path == "/passkeys":
            self._passkeys_page()
            return
        if path in ("/check", "/auth/check"):
            user = self.current_user()
            status = HTTPStatus.UNAUTHORIZED if not user else HTTPStatus.NO_CONTENT
            site = self.headers.get("X-Forwarded-Host", "").split(",", 1)[0].split(":", 1)[0]
            if user and site:
                try:
                    if not access_control.can_access(ACCESS_DB, user, site):
                        status = HTTPStatus.FORBIDDEN
                except Exception:
                    status = HTTPStatus.SERVICE_UNAVAILABLE
            self.send_response(status)
            self._security_headers()
            if user and status == HTTPStatus.NO_CONTENT:
                self.send_header("X-GPTAdmin-User", user)
            self.end_headers()
            return
        if path == "/admin":
            self._admin_page()
            return
        if path == "/invite":
            self._invite_page()
            return
        if path in ("/logout", "/auth/logout"):
            self.send_response(HTTPStatus.FOUND)
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}=; Domain={COOKIE_DOMAIN}; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
            )
            self.send_header(
                "Location", safe_rd(query.get("rd", ["https://auth.bezrabotnyi.com/login"])[0])
            )
            self.end_headers()
            return
        if path in ("/", "/login", "/auth/login"):
            redirect = safe_rd(query.get("rd", [DEFAULT_REDIRECT])[0])
            self._login_page(redirect, bool(query.get("err", [""])[0]))
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/admin":
            data = self._form_data()
            admin = self._admin_user()
            if data is None or not admin:
                self._send_json(403, {"error": "request rejected"})
                return
            action = data.get("action", [""])[0]
            if action == "create":
                username = data.get("username", [""])[0]
                display_name = data.get("display_name", [""])[0]
                sites = data.get("sites", [])
                try:
                    token, _ = access_control.create_invite(ACCESS_DB, username, display_name, sites)
                    invite_url = "https://auth.bezrabotnyi.com/invite#token=" + urllib.parse.quote(token, safe="-_")
                    self._admin_page("Пользователь добавлен. Скопируйте ссылку и передайте её пользователю.", invite_url)
                except ValueError:
                    self._admin_page("Проверьте логин и список сайтов.", status=400)
                except Exception:
                    self._admin_page("Не удалось создать пользователя. Проверьте, не занят ли логин.", status=400)
                return
            if action == "update":
                username = data.get("username", [""])[0]
                sites = data.get("sites", [])
                state = data.get("status", [""])[0]
                try:
                    saved = access_control.update_user(ACCESS_DB, username, sites, state)
                except Exception:
                    saved = False
                self._admin_page(
                    "Доступ сохранён." if saved else "Не удалось сохранить изменения.",
                    status=200 if saved else 400,
                )
                return
            self._admin_page("Неизвестная операция.", status=400)
            return
        if parsed.path == "/invite":
            if not INVITE_SETUP_ENABLED:
                self._invite_page(status=503)
                return
            data = self._form_data()
            if data is None:
                self._send_json(403, {"error": "request rejected"})
                return
            token = data.get("token", [""])[0]
            password = data.get("password", [""])[0]
            confirmation = data.get("password_confirm", [""])[0]
            if password != confirmation:
                self._invite_page("Пароли не совпадают. Попробуйте ещё раз.", status=400, token=token)
                return
            try:
                username = access_control.consume_invite(ACCESS_DB, token, password)
            except Exception:
                username = None
            if username:
                self._invite_page(success=True)
            else:
                self._invite_page(
                    "Ссылка недействительна, истекла или уже использована. Попросите новую.",
                    status=410,
                    token=token,
                )
            return
        if parsed.path.startswith("/passkey/"):
            module = passkeys_module()
            if module is None:
                self._send_json(404, {"error": "not found"})
                return
            if not self._require_passkey_write():
                return
            data = self._read_json()
            if data is None:
                self._passkey_failure(400)
                return
            routes = {
                "/passkey/auth/options": self._start_passkey_authentication,
                "/passkey/auth/verify": self._finish_passkey_authentication,
                "/passkey/register/options": self._start_passkey_registration,
                "/passkey/register/verify": self._finish_passkey_registration,
                "/passkey/revoke": self._revoke_passkey,
            }
            handler = routes.get(parsed.path)
            if handler is None:
                self._send_json(404, {"error": "not found"})
                return
            try:
                handler(module, data)
            except Exception:
                print("[auth] passkey request rejected", flush=True)
                self._passkey_failure()
            return
        if parsed.path not in ("/login", "/auth/login"):
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            return
        if self.headers.get("Origin", "") != "https://auth.bezrabotnyi.com":
            self._send_json(403, {"error": "request rejected"})
            return
        cookies = parse_cookie(self.headers.get("Cookie", ""))
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            self._send_json(403, {"error": "request rejected"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length < 1 or length > MAX_JSON_BODY:
            self._send_json(400, {"error": "request rejected"})
            return
        data = urllib.parse.parse_qs(self.rfile.read(length).decode(errors="replace"))
        csrf_cookie_name = data.get("csrf_cookie_name", [CSRF_COOKIE])[0]
        csrf_cookie = (
            cookies.get(csrf_cookie_name, "")
            if valid_csrf_cookie_name(csrf_cookie_name)
            else ""
        )
        csrf_form = data.get("csrf", [""])[0]
        if not csrf_cookie or not hmac.compare_digest(csrf_cookie, csrf_form):
            self._send_json(403, {"error": "request rejected"})
            return
        ajax_login = self.headers.get("X-SSS-Login", "") == "1"
        username = data.get("username", [""])[0].strip()
        password = data.get("password", [""])[0]
        redirect = safe_rd(data.get("rd", [DEFAULT_REDIRECT])[0])
        verified_username = authenticate_password(username, password)
        if verified_username:
            session_cookie = (
                f"{COOKIE_NAME}={make_token(verified_username)}; Domain={COOKIE_DOMAIN}; "
                f"Path=/; Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Lax"
            )
            if ajax_login:
                self._send_json(
                    200,
                    {"ok": True, "redirect": redirect},
                    headers=(("Set-Cookie", session_cookie),),
                )
                return
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Set-Cookie", session_cookie)
            self.send_header("Location", redirect)
        else:
            if ajax_login:
                self._send_json(401, {"ok": False})
                return
            self.send_response(HTTPStatus.FOUND)
            self.send_header(
                "Location", "/login?err=1&rd=" + urllib.parse.quote(redirect, safe="")
            )
        self.end_headers()


if __name__ == "__main__":
    access_control.initialize(ACCESS_DB, read_site_catalog(), read_users())
    http.server.ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
