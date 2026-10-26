import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cookie_auth


class LoginRedirectFragmentTests(unittest.TestCase):
    def test_rendered_login_page_uses_fragment_merge_for_both_login_methods(self) -> None:
        handler = object.__new__(cookie_auth.Handler)
        handler.current_user = lambda: None
        handler._send_html = Mock()
        with patch.object(cookie_auth, "passkeys_module", return_value=object()):
            handler._login_page("https://notify.bezrabotnyi.com/admin/")

        page = handler._send_html.call_args.args[0]
        self.assertIn(cookie_auth.LOGIN_FRAGMENT_SCRIPT, page)
        self.assertIn("location.assign(redirectWithLoginFragment(result.redirect))", page)
        self.assertIn("location.href=redirectWithLoginFragment(REDIRECT)", page)
        self.assertIn("location.assign(redirectWithLoginFragment(REDIRECT))", page)

    def redirect_in_browser(self, current_url: str, redirect: str) -> str:
        script = (
            f"globalThis.location = new URL({json.dumps(current_url)});\n"
            + cookie_auth.LOGIN_FRAGMENT_SCRIPT
            + f"\nconsole.log(redirectWithLoginFragment({json.dumps(redirect)}));\n"
        )
        result = subprocess.run(
            ["node", "-e", script], capture_output=True, text=True, check=True, timeout=5
        )
        return result.stdout.strip()

    def test_inherits_hash_route_from_auth_url_when_rd_has_no_fragment(self) -> None:
        self.assertEqual(
            "https://notify.bezrabotnyi.com/admin/#/ai",
            self.redirect_in_browser(
                "https://auth.bezrabotnyi.com/login?rd=https://notify.bezrabotnyi.com/admin/#/ai",
                "https://notify.bezrabotnyi.com/admin/",
            ),
        )

    def test_keeps_fragment_already_present_in_rd(self) -> None:
        self.assertEqual(
            "https://notify.bezrabotnyi.com/admin/#/users",
            self.redirect_in_browser(
                "https://auth.bezrabotnyi.com/login?rd=https://notify.bezrabotnyi.com/admin/#/ai",
                "https://notify.bezrabotnyi.com/admin/#/users",
            ),
        )


if __name__ == "__main__":
    unittest.main()
