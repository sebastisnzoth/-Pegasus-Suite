import importlib.util
import pathlib
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mobile_security", ROOT / "mobile_security.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ArchiveInspectionTests(unittest.TestCase):
    def test_valid_apk_returns_verified_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "example.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", "placeholder")
            facts = module.MobileSecurityTools.inspect_mobile_archive(str(path), ".apk")
            self.assertTrue(facts["manifest_present"])
            self.assertEqual(len(facts["sha256"]), 64)
            self.assertEqual(facts["entries"], 1)

    def test_missing_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "bad.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("x.txt", "x")
            with self.assertRaisesRegex(ValueError, "manifest"):
                module.MobileSecurityTools.inspect_mobile_archive(str(path), ".apk")

    def test_ipa_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "app.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Test.app/Info.plist", "data")
            facts = module.MobileSecurityTools.inspect_mobile_archive(str(path), ".ipa")
            self.assertTrue(facts["manifest_present"])

    def test_not_zip_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "fake.apk"
            path.write_text("not a zip")
            with self.assertRaisesRegex(ValueError, "ZIP"):
                module.MobileSecurityTools.inspect_mobile_archive(str(path), ".apk")


if __name__ == "__main__":
    unittest.main()
