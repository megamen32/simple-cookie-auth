# simple-cookie-auth

Самая тупая cookie-защита для людей, которых уже достал HTTP Basic Auth.

Это маленький локальный login-сервис для reverse proxy:

- пользователь один раз вводит пароль на странице login;
- сервис выдаёт подписанную cookie;
- Nginx или Caddy тихо спрашивает локальный `/check`;
- приложение за reverse proxy вообще не знает про логины и bearer-заголовки.

Я написал эту штуку после того, как «правильное» решение, которое мне насоветовали, превратилось в огромную систему из компонентов, которые надо сначала изучить, а потом ещё поддерживать. Здесь всё наоборот: один Python-файл, один htpasswd, один secret-файл и один кусок конфига proxy.

Это не Authentik, не Keycloak, не OAuth-провайдер и не корпоративная IAM-платформа. Это удобная стенка перед домашней админкой, внутренним UI или сервисом, у которого нет собственной авторизации.

## Что происходит

```text
browser -- cookie --> nginx/caddy -- local /check --> simple-cookie-auth
                         |
                         +-- 204: проксировать приложение
                         +-- 401: отправить browser на /login
```

Cookie подписывается HMAC-SHA256. Её содержимое можно прочитать, но изменить username или срок действия без secret нельзя. Cookie имеет `Secure`, `HttpOnly` и `SameSite=Lax`.

## Установка

Нужен Python 3.10+ на Linux. Внешних Python-зависимостей нет.

```bash
sudo install -d -m 700 /etc/simple-cookie-auth
sudo install -m 755 simple_cookie_auth.py /usr/local/lib/simple-cookie-auth/simple_cookie_auth.py

# Создать парольный файл APR1.
sudo htpasswd -m -c /etc/simple-cookie-auth/users.htpasswd admin

# Создать секрет подписи и больше никому его не показывать.
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/simple-cookie-auth/secret'

sudo chmod 600 /etc/simple-cookie-auth/users.htpasswd /etc/simple-cookie-auth/secret
```

Скопируй [systemd/simple-cookie-auth.service](systemd/simple-cookie-auth.service) в `/etc/systemd/system/`, замени `example.com` на свой домен и запусти:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now simple-cookie-auth
curl -i http://127.0.0.1:18991/healthz
```

Сервис должен слушать только localhost. Наружу публикуется только домен auth через Nginx или Caddy.

## Nginx

Готовый пример находится в [examples/nginx.conf](examples/nginx.conf). В server block нужно заменить:

- `auth.example.com` на домен login-сервиса;
- `127.0.0.1:9000` на своё приложение;
- `example.com` в cookie domain на свой базовый домен.

Для WebSocket добавь стандартную map-переменную:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
```

Не публикуй `/check` напрямую. В примере он помечен `internal`.

## Caddy

Минимальный пример для Caddy 2 — [examples/Caddyfile](examples/Caddyfile). Он использует `forward_auth` и превращает `401` в redirect на login.

## Настройки через environment

CLI-флаги имеют приоритет над defaults и могут быть заменены переменными:

```text
SIMPLE_COOKIE_AUTH_HOST
SIMPLE_COOKIE_AUTH_PORT
SIMPLE_COOKIE_AUTH_USERS
SIMPLE_COOKIE_AUTH_SECRET
SIMPLE_COOKIE_AUTH_COOKIE_DOMAIN
SIMPLE_COOKIE_AUTH_COOKIE_NAME
SIMPLE_COOKIE_AUTH_TTL
SIMPLE_COOKIE_AUTH_DEFAULT_REDIRECT
```

## Честные ограничения

Это простой компромисс, а не «самый хороший auth»:

- cookie — bearer по смыслу: если её украли, её можно использовать до истечения TTL;
- нет ролей, MFA, OAuth, SSO и базы сессий;
- для public-facing login добавь rate limit на proxy;
- используй HTTPS всегда;
- не ставь эту защиту перед API, где нужна машинная авторизация;
- если нужен enterprise auth, бери Authentik, Authelia, Keycloak или внешний IdP.

Смысл проекта не в том, что сложные системы плохие. Смысл в том, что иногда тебе нужна одна парольная стенка перед одним UI — и не хочется тратить неделю на изучение сложной системы.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT. См. [LICENSE](LICENSE).
