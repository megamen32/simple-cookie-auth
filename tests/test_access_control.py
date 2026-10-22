import http.client
import re
import threading
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode
from http.server import ThreadingHTTPServer

import access_control
import cookie_auth


class AccessControlTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "access.sqlite3"
        access_control.initialize(
            self.db,
            ["one.bezrabotnyi.com", "two.bezrabotnyi.com"],
            {"owner": "$apr1$test$hash"},
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_legacy_owner_is_super_admin_and_new_user_is_site_scoped(self):
        self.assertTrue(access_control.is_admin(self.db, "owner"))
        self.assertTrue(access_control.can_access(self.db, "owner", "two.bezrabotnyi.com"))

        token, _ = access_control.create_invite(
            self.db, "oleg", "Олег", ["one.bezrabotnyi.com"]
        )
        self.assertFalse(access_control.can_access(self.db, "oleg", "one.bezrabotnyi.com"))
        self.assertEqual("oleg", access_control.consume_invite(
            self.db, token, "a long unique password"
        ))
        user = access_control.get_user(self.db, "oleg")
        self.assertTrue(access_control.verify_password(
            "a long unique password", user["password_salt"], user["password_hash"]
        ))
        self.assertTrue(access_control.can_access(self.db, "oleg", "one.bezrabotnyi.com"))
        self.assertFalse(access_control.can_access(self.db, "oleg", "two.bezrabotnyi.com"))
        self.assertIsNone(access_control.consume_invite(self.db, token, "another long password"))

    def test_permissions_change_immediately_and_disable_revokes_access(self):
        token, _ = access_control.create_invite(
            self.db, "oleg", "Олег", ["one.bezrabotnyi.com"]
        )
        access_control.consume_invite(self.db, token, "a long unique password")
        self.assertTrue(access_control.can_access(self.db, "oleg", "one.bezrabotnyi.com"))
        self.assertTrue(access_control.update_user(
            self.db, "oleg", ["two.bezrabotnyi.com"], "active"
        ))
        self.assertFalse(access_control.can_access(self.db, "oleg", "one.bezrabotnyi.com"))
        self.assertTrue(access_control.can_access(self.db, "oleg", "two.bezrabotnyi.com"))
        self.assertTrue(access_control.update_user(self.db, "oleg", [], "disabled"))
        self.assertFalse(access_control.can_access(self.db, "oleg", "two.bezrabotnyi.com"))

    def test_invite_is_single_use_and_expired_invite_cannot_be_consumed(self):
        token, _ = access_control.create_invite(self.db, "oleg", "Олег", [], ttl=-1)
        self.assertIsNone(access_control.consume_invite(self.db, token, "a long unique password"))

    def test_unknown_hosts_cannot_be_assigned(self):
        with self.assertRaises(ValueError):
            access_control.create_invite(self.db, "oleg", "Олег", ["unknown.bezrabotnyi.com"])


class AccessControlHttpTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        self.db = root / "access.sqlite3"
        self.secret = root / "secret"
        self.secret.write_bytes(b"integration-test-signing-secret")
        access_control.initialize(
            self.db,
            ["one.bezrabotnyi.com", "two.bezrabotnyi.com"],
            {"owner": "$apr1$test$hash"},
        )
        self.old_access_db, self.old_secret = cookie_auth.ACCESS_DB, cookie_auth.SECRET_FILE
        cookie_auth.ACCESS_DB = str(self.db)
        cookie_auth.SECRET_FILE = str(self.secret)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), cookie_auth.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        cookie_auth.ACCESS_DB, cookie_auth.SECRET_FILE = self.old_access_db, self.old_secret
        self.tempdir.cleanup()

    def request(self, method, path, headers=None, body=""):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read().decode("utf-8")
        conn.close()
        return result

    @staticmethod
    def csrf_from(response_headers, body):
        name = re.search(r'name="csrf_cookie_name" value="([^"]+)"', body).group(1)
        value = next(v for k, v in response_headers.items() if k.lower() == "set-cookie").split(";", 1)[0].split("=", 1)[1]
        return name, value

    def test_admin_invite_sets_password_once_and_check_enforces_per_host(self):
        owner_cookie = "gptadmin_auth=" + cookie_auth.make_token("owner")
        status, headers, body = self.request("GET", "/admin", {"Cookie": owner_cookie})
        self.assertEqual(200, status)
        csrf_name, csrf = self.csrf_from(headers, body)
        form = urlencode([
            ("action", "create"), ("username", "oleg"), ("display_name", "Олег"),
            ("sites", "one.bezrabotnyi.com"), ("csrf", csrf), ("csrf_cookie_name", csrf_name),
        ])
        status, _, body = self.request("POST", "/admin", {
            "Cookie": owner_cookie + "; " + csrf_name + "=" + csrf,
            "Origin": "https://auth.bezrabotnyi.com",
            "Content-Type": "application/x-www-form-urlencoded",
        }, form)
        self.assertEqual(200, status)
        invite_token = re.search(r"/invite#token=([A-Za-z0-9_-]+)", body).group(1)

        status, invite_headers, invite_body = self.request("GET", "/invite")
        self.assertEqual(200, status)
        self.assertNotIn(invite_token, invite_body)
        csrf_name, csrf = self.csrf_from(invite_headers, invite_body)
        setup_form = urlencode([
            ("token", invite_token), ("password", "long unique password for Oleg"),
            ("password_confirm", "long unique password for Oleg"),
            ("csrf", csrf), ("csrf_cookie_name", csrf_name),
        ])
        status, _, body = self.request("POST", "/invite", {
            "Cookie": csrf_name + "=" + csrf,
            "Origin": "https://auth.bezrabotnyi.com",
            "Content-Type": "application/x-www-form-urlencoded",
        }, setup_form)
        self.assertEqual(200, status)
        self.assertIn("Пароль установлен", body)

        user_cookie = "gptadmin_auth=" + cookie_auth.make_token("oleg")
        status, _, _ = self.request("GET", "/check", {
            "Cookie": user_cookie, "X-Forwarded-Host": "one.bezrabotnyi.com",
        })
        self.assertEqual(204, status)
        status, _, _ = self.request("GET", "/check", {
            "Cookie": user_cookie, "X-Forwarded-Host": "two.bezrabotnyi.com",
        })
        self.assertEqual(403, status)
        status, _, _ = self.request("GET", "/admin", {"Cookie": user_cookie})
        self.assertEqual(403, status)

        previous = cookie_auth.ADMIN_ENABLED
        previous_invites = cookie_auth.INVITE_SETUP_ENABLED
        cookie_auth.ADMIN_ENABLED = False
        cookie_auth.INVITE_SETUP_ENABLED = False
        try:
            status, _, _ = self.request("GET", "/admin", {"Cookie": owner_cookie})
            self.assertEqual(403, status)
            status, _, body = self.request("GET", "/invite#token=not-sent")
            self.assertEqual(503, status)
            self.assertNotIn("not-sent", body)
        finally:
            cookie_auth.ADMIN_ENABLED = previous
            cookie_auth.INVITE_SETUP_ENABLED = previous_invites

        status, _, _ = self.request("POST", "/invite", {
            "Cookie": csrf_name + "=" + csrf,
            "Origin": "https://auth.bezrabotnyi.com",
            "Content-Type": "application/x-www-form-urlencoded",
        }, setup_form)
        self.assertEqual(410, status)


if __name__ == "__main__":
    unittest.main()
