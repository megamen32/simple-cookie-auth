# Тестовый вход в общий SSO

Для разрешённых проверок защищённых сайтов используйте существующую учётку
`testlogin`. Она активна, не legacy, имеет `is_admin=1`: это та же политика
SSO-доступа, что у администратора, включая все 37 зарегистрированных сайтов
на 26.10.2026. Это не разрешение менять чужие данные или выполнять внешние
действия. Права внутри отдельных приложений проверяются отдельно.

Пароль находится в общем Simple Secret Storage под именем
`sso.qa.admin-equivalent`. Не запрашивайте его повторно и не извлекайте в чат,
аргументы, environment, файлы, снимки либо логи. Используйте фиксированный
потребитель `/home/roomhacker/simple-cookie-auth/scripts/sso-qa-fill.py`:
он получает секрет только через stdin, заполняет форму через поддерживаемый
`agent-browser eval --stdin` и не отправляет её.

На server-100 выберите собственные короткие session/namespace. Пример для
новой собственной браузерной сессии; сохраняйте одинаковые параметры во всех
вызовах:

```sh
agent-browser --session qa-sso --namespace qa-sso --auto-connect false --headed false --idle-timeout 300000 open 'https://auth.bezrabotnyi.com/login?rd=https%3A%2F%2Fagent.bezrabotnyi.com%2F'
agent-browser --session qa-sso --namespace qa-sso --auto-connect false --headed false --idle-timeout 300000 snapshot -i
sss-run sso.qa.admin-equivalent -- /home/roomhacker/simple-cookie-auth/scripts/sso-qa-fill.py --session qa-sso --namespace qa-sso
```

Нажмите «Войти паролем» **один раз** через актуальный ref из snapshot. Затем
читайте URL и snapshot до завершения перехода: краткое состояние disabled
после нажатия означает ожидание, а не отказ. Успех — реальная защищённая
страница приложения, а не только исчезновение формы. Не выводите cookies,
значения password-полей или URL с возможным секретным fragment. При ошибке
или неоднозначном состоянии сначала снимите и осмотрите безопасный screenshot
той же сессии, затем проверьте результат до повторного действия. Закройте
только собственную сессию:

```sh
agent-browser --session qa-sso --namespace qa-sso --auto-connect false --headed false --idle-timeout 300000 close
```

Другой разрешённый сайт можно указать в `rd`; потребитель принимает только
настоящую форму `/login` на `https://auth.bezrabotnyi.com`. Недоступный GPTAdmin
не запрещает этот штатный native CLI. Не подключайтесь к личному Chrome.

Владелец исходников SSO: `/home/roomhacker/simple-cookie-auth`. Для обычного
QA-входа не нужны создание аккаунта, изменение ролей, `.htpasswd_router`,
перезапуск SSO или правка старого infra template. Не повторяйте invite/create/
activation: существующая учётка уже подготовлена.

Проверка 26.10.2026: чтение действующей SQLite подтвердило active/nonlegacy/
is_admin=1; реальный вход `testlogin` через SSS → stdin-потребитель → форму
открыл `https://agent.bezrabotnyi.com/`, title `Agent Herder`, навигацию и
список чатов. Выполнено одно нажатие входа; сообщений, задач и звонков не было.
