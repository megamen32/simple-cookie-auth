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
from http import HTTPStatus


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


def read_secret() -> bytes:
    """Read the signing secret and fail closed when it is absent or empty."""
    with open(SECRET_FILE, "rb") as secret_file:
        secret = secret_file.read().strip()
    if not secret:
        raise RuntimeError(f"empty auth secret: {SECRET_FILE}")
    return secret


def read_users() -> dict[str, str]:
    """Read Apache htpasswd-compatible user hashes from the configured file."""
    users: dict[str, str] = {}
    with open(HTPASSWD, "r", encoding="utf-8") as users_file:
        for line in users_file:
            line = line.strip()
            if not line or ":" not in line:
                continue
            user, hashed = line.split(":", 1)
            users[user] = hashed
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
    """Return the exact verified account, including the legacy blank-user fallback."""
    users = read_users()
    if not username and users:
        username = next(iter(users))
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
        print(
            "%s - - [%s] %s"
            % (self.client_address[0], self.log_date_time_string(), fmt % args),
            flush=True,
        )

    def current_user(self) -> str | None:
        cookies = parse_cookie(self.headers.get("Cookie", ""))
        return check_token(cookies.get(COOKIE_NAME, ""))

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
    location.href=REDIRECT;
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
    location.assign(result.redirect);
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
    password.value='';status.textContent='Ключ добавлен';location.assign(REDIRECT);
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
        if path == "/passkeys":
            self._passkeys_page()
            return
        if path in ("/check", "/auth/check"):
            user = self.current_user()
            self.send_response(HTTPStatus.NO_CONTENT if user else HTTPStatus.UNAUTHORIZED)
            self._security_headers()
            if user:
                self.send_header("X-GPTAdmin-User", user)
            self.end_headers()
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
    http.server.ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
