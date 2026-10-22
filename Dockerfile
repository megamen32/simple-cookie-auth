FROM python@sha256:f1927c75e81efd1e091dbd64b6c0ecaa5630b38635a3d1c04034ac636e1f94c8

ENV PYTHONUNBUFFERED=1 \
    GPTADMIN_COOKIE_AUTH_HOST=0.0.0.0 \
    GPTADMIN_COOKIE_AUTH_PORT=18991 \
    GPTADMIN_COOKIE_AUTH_HTPASSWD=/run/secrets/htpasswd \
    GPTADMIN_COOKIE_AUTH_SECRET_FILE=/run/secrets/cookie_secret \
    GPTADMIN_COOKIE_AUTH_DOMAIN=.example.com \
    GPTADMIN_COOKIE_AUTH_PASSKEYS_ENABLED=1 \
    GPTADMIN_COOKIE_AUTH_PASSKEY_DB=/var/lib/gptadmin-cookie-auth/passkeys.sqlite3 \
    GPTADMIN_COOKIE_AUTH_ACCESS_DB=/var/lib/gptadmin-cookie-auth/access.sqlite3 \
    GPTADMIN_COOKIE_AUTH_SITE_CATALOG=/app/sites.json \
    GPTADMIN_COOKIE_AUTH_ADMIN_ENABLED=1 \
    GPTADMIN_COOKIE_AUTH_INVITE_SETUP_ENABLED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt
COPY cookie_auth.py passkeys.py access_control.py sites.json /app/

HEALTHCHECK --interval=30s --timeout=4s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18991/healthz', timeout=3).close()" || exit 1

EXPOSE 18991
ENTRYPOINT ["python", "/app/cookie_auth.py"]
