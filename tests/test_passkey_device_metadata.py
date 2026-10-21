from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
PASSKEY_MODULE = ROOT / "passkeys.py"


class PasskeyDeviceMetadataTests(unittest.TestCase):
    def test_login_page_uses_two_gestures_for_registration(self) -> None:
        source = (ROOT / "cookie_auth.py").read_text(encoding="utf-8")
        self.assertIn("let pendingRegistrationOptions=null", source)
        self.assertIn("Продолжить с Touch ID", source)
        gesture_branch = source[
            source.index("const options=pendingRegistrationOptions;"):
            source.index("const credential=await createPromise")
        ]
        self.assertIn("navigator.credentials.create({{publicKey:options}})", gesture_branch)
        self.assertNotIn("await ", gesture_branch)

    def test_registration_binds_user_agent_and_browser_reported_cores(self) -> None:
        sys.path.insert(0, str(ROOT))
        try:
            import cookie_auth

            handler = object.__new__(cookie_auth.Handler)
            handler.current_user = lambda: None
            handler.headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"}
            handler._passkey_failure = Mock()
            handler._send_json = Mock()
            module = SimpleNamespace(
                CHALLENGE_TTL_SECONDS=300,
                RP_ID="auth.bezrabotnyi.com",
                account_generation=Mock(return_value=b"generation"),
                principal_for_registration=Mock(return_value=(b"user-handle", [])),
                create_challenge=Mock(return_value=("challenge-id", b"challenge")),
                webauthn_api=Mock(return_value=(
                    SimpleNamespace(
                        generate_registration_options=Mock(return_value=object()),
                        options_to_json=Mock(return_value='{"challenge":"Y2hhbGxlbmdl","user":{"id":"aGFuZGxl"}}'),
                    ),
                    SimpleNamespace(NONE="none"),
                    SimpleNamespace(PLATFORM="platform"),
                    lambda **kwargs: kwargs,
                    lambda **kwargs: kwargs,
                    SimpleNamespace(REQUIRED="required"),
                    SimpleNamespace(REQUIRED="required"),
                )),
            )
            with patch.object(cookie_auth, "read_users", return_value={"roomhacker": "hash"}), \
                 patch.object(cookie_auth, "verify_password", return_value=True), \
                 patch.object(cookie_auth, "read_secret", return_value=b"test-signing-secret"):
                handler._start_passkey_registration(module, {
                    "username": "roomhacker", "password": "fixture-password",
                    "label": "Mac", "logical_cores": 10,
                })
            state = module.create_challenge.call_args.args[1]
            self.assertEqual("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)", state["user_agent"])
            self.assertEqual(10, state["logical_cores"])
            self.assertEqual("Mac · 10 ядер", state["label"])
        finally:
            if str(ROOT) in sys.path:
                sys.path.remove(str(ROOT))


class PasskeyStoreMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        sys.path.insert(0, str(ROOT))
        import passkeys
        self.passkeys = passkeys
        self.tempdir = tempfile.TemporaryDirectory()
        self.old_db, self.old_ready = passkeys.DB_PATH, passkeys.READY_PATH
        passkeys.DB_PATH = Path(self.tempdir.name) / "passkeys.sqlite3"
        passkeys.READY_PATH = Path(str(passkeys.DB_PATH) + ".initialized")

    def tearDown(self) -> None:
        self.passkeys.DB_PATH, self.passkeys.READY_PATH = self.old_db, self.old_ready
        self.tempdir.cleanup()
        if str(ROOT) in sys.path:
            sys.path.remove(str(ROOT))

    def test_store_round_trip_and_migrate_existing_records(self) -> None:
        store = self.passkeys
        with sqlite3.connect(store.DB_PATH) as conn:
            conn.executescript(
                "CREATE TABLE principals (username TEXT PRIMARY KEY, generation BLOB NOT NULL, user_handle BLOB NOT NULL);"
                "CREATE TABLE credentials (credential_id BLOB NOT NULL PRIMARY KEY, username TEXT NOT NULL, "
                "generation BLOB NOT NULL, user_handle BLOB NOT NULL, public_key BLOB NOT NULL, "
                "sign_count INTEGER NOT NULL DEFAULT 0, label TEXT NOT NULL, created_at INTEGER NOT NULL, "
                "last_used_at INTEGER NOT NULL DEFAULT 0, backed_up INTEGER NOT NULL DEFAULT 0);"
            )
            conn.execute("INSERT INTO principals VALUES(?,?,?)", ("fixture", b"generation", b"handle"))
            conn.execute(
                "INSERT INTO credentials(credential_id,username,generation,user_handle,public_key,sign_count,label,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (b"legacy", "fixture", b"generation", b"handle", b"public-key", 0, "Mac", 123),
            )
        store.READY_PATH.write_text("passkey-store-v1\n", encoding="ascii")

        legacy = store.list_credentials("fixture", b"generation")[0]
        self.assertEqual(b"legacy", legacy["credential_id"])
        self.assertEqual("", legacy["user_agent"])
        self.assertIsNone(legacy["logical_cores"])

        handle, _ = store.principal_for_registration("fixture", b"generation")
        self.assertTrue(store.save_credential(
            credential_id=b"new", username="fixture", generation=b"generation",
            user_handle=handle, public_key=b"public-key", sign_count=0,
            label="Mac · 10 ядер", backed_up=False,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)", logical_cores=10,
        ))
        new = next(row for row in store.list_credentials("fixture", b"generation") if row["credential_id"] == b"new")
        self.assertEqual("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)", new["user_agent"])
        self.assertEqual(10, new["logical_cores"])


if __name__ == "__main__":
    unittest.main()
