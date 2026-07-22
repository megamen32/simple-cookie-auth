import http.client
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

from simple_cookie_auth import Config, ConfiguredHTTPServer, check_token


class SimpleCookieAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        hash_result = subprocess.run(
            ["openssl", "passwd", "-apr1", "-salt", "testsalt", "-stdin"],
            input=b"correct horse battery staple\n",
            stdout=subprocess.PIPE,
            check=True,
        )
        (root / "users.htpasswd").write_text(
            f"admin:{hash_result.stdout.decode().strip()}\n", encoding="utf-8"
        )
        (root / "secret").write_bytes(b"test-secret-that-is-long-enough")
        self.config = Config(
            host="127.0.0.1",
            port=0,
            users_file=root / "users.htpasswd",
            secret_file=root / "secret",
            cookie_name="simple_auth",
            cookie_domain=".example.test",
            session_ttl=3600,
            default_redirect="https://example.test/",
        )
        self.server = ConfiguredHTTPServer((self.config.host, self.config.port), self.config)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def request(self, method: str, path: str, headers=None, body: str | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_login_issues_cookie_that_check_accepts(self) -> None:
        status, _, _ = self.request("GET", "/check")
        self.assertEqual(401, status)

        body = urlencode({"username": "admin", "password": "correct horse battery staple", "rd": "/"})
        status, headers, _ = self.request(
            "POST",
            "/login",
            {"Content-Type": "application/x-www-form-urlencoded"},
            body,
        )
        self.assertEqual(302, status)
        cookie = next(value for key, value in headers.items() if key.lower() == "set-cookie").split(";", 1)[0]
        self.assertIn("HttpOnly", next(value for key, value in headers.items() if key.lower() == "set-cookie"))

        status, check_headers, _ = self.request("GET", "/check", {"Cookie": cookie})
        self.assertEqual(204, status)
        self.assertEqual("admin", check_headers["X-Auth-User"])

    def test_modified_cookie_is_rejected(self) -> None:
        body = urlencode({"username": "admin", "password": "correct horse battery staple", "rd": "/"})
        _, headers, _ = self.request(
            "POST",
            "/login",
            {"Content-Type": "application/x-www-form-urlencoded"},
            body,
        )
        cookie = next(value for key, value in headers.items() if key.lower() == "set-cookie").split(";", 1)[0]
        name, value = cookie.split("=", 1)
        status, _, _ = self.request("GET", "/check", {"Cookie": f"{name}={value[:-1]}x"})
        self.assertEqual(401, status)

    def test_external_redirect_is_replaced_with_default(self) -> None:
        status, _, body = self.request("GET", "/login?rd=https%3A%2F%2Fevil.example%2F")
        self.assertEqual(200, status)
        self.assertNotIn(b"evil.example", body)
        self.assertIn(b"example.test", body)

    def test_missing_secret_fails_closed(self) -> None:
        secret = self.config.secret_file
        secret.unlink()
        self.assertIsNone(check_token(self.config, "anything.anything"))


if __name__ == "__main__":
    unittest.main()
