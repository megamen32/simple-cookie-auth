import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sso-qa-fill.py"
SPEC = importlib.util.spec_from_file_location("sso_qa_fill", SCRIPT)
SQA_FILL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SQA_FILL)


class SsoQaFillTests(unittest.TestCase):
    def test_browser_command_uses_the_session_idle_timeout(self):
        command = SQA_FILL.build_browser_command("qa-session", "qa-namespace", "300000")
        timeout_at = command.index("--idle-timeout")
        self.assertEqual("300000", command[timeout_at + 1])
        self.assertEqual("qa-session", command[command.index("--session") + 1])
        self.assertEqual("qa-namespace", command[command.index("--namespace") + 1])


if __name__ == "__main__":
    unittest.main()
