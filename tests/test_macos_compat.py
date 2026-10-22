import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class MacCompatTests(unittest.TestCase):
    def test_main_script_parses(self):
        ast.parse((ROOT / "Pegasus-Suite.py").read_text(encoding="utf-8"))
    def test_compat_imports_parse(self):
        ast.parse((ROOT / "pegasus_imports.py").read_text(encoding="utf-8"))
    def test_darwin_terminal_supported(self):
        code = (ROOT / "Pegasus-Suite.py").read_text(encoding="utf-8")
        self.assertIn("('Linux', 'Darwin')", code)
    def test_installer_does_not_use_sudo(self):
        script = (ROOT / "install-macos.sh").read_text(encoding="utf-8")
        self.assertNotIn("sudo ", script)
        self.assertIn("python3 -m venv .venv", script)
        self.assertIn("set -eu", script)

if __name__ == "__main__":
    unittest.main()
