"""Regression tests for OSINT command execution and evidence integrity."""
import ast
import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "osint.py"


class TestOsintSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(SOURCE))

    def test_no_fabricated_whois_records(self):
        self.assertNotIn("Simulated WHOIS Information", self.source)
        self.assertNotIn("Example Registrar, LLC", self.source)
        self.assertIn("WHOIS unavailable: no verified data returned.", self.source)

    def test_no_shell_interpolated_dns_commands(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr == "system":
                    for arg in node.args:
                        self.assertNotIsInstance(arg, ast.JoinedStr, "Dynamic os.system is unsafe")

    def test_dns_uses_argument_arrays(self):
        for tool in ("dig", "nslookup"):
            self.assertIn('subprocess.run(["' + tool + '",', self.source)

    def test_domain_checks_present_in_whois_and_dns(self):
        self.assertGreaterEqual(self.source.count("Invalid domain name."), 2)


if __name__ == "__main__":
    unittest.main()
