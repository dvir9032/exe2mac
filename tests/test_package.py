"""Packaging tests. Bundle structure and the launcher are tested on any POSIX
host; signing and .dmg creation are exercised only on macOS."""
import os
import platform
import plistlib
import shutil
import subprocess
import tempfile
import unittest

from recompiler import decoder as dec

ROOT = os.path.dirname(os.path.dirname(__file__))
EXE = os.path.join(ROOT, "test", "hello.exe")
GOLDEN = os.path.join(ROOT, "test", "golden", "hello.stdout")
CC = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
ON_MAC = platform.system() == "Darwin"


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from recompiler.package import package
        cls.td = tempfile.TemporaryDirectory()
        cls.res = package(EXE, cls.td.name, app_name="Hello")
        cls.app = cls.res["app"]

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_bundle_layout_and_info_plist(self):
        c = self.app / "Contents"
        with open(c / "Info.plist", "rb") as f:
            info = plistlib.load(f)
        self.assertEqual(info["CFBundleExecutable"], "hello")
        self.assertEqual(info["CFBundlePackageType"], "APPL")
        self.assertEqual(info["CFBundleIdentifier"], "org.exe2mac.hello")
        self.assertEqual(info["LSArchitecturePriority"], ["arm64"])
        for rel in ("MacOS/hello", "MacOS/hello-guest"):
            self.assertTrue(os.access(c / rel, os.X_OK), rel)
        self.assertTrue((c / "Resources" / "THIRD_PARTY_NOTICES.md").is_file())
        self.assertEqual((c / "PkgInfo").read_text(), "APPL????")

    def test_launcher_passes_stdout_and_exit_code_through(self):
        env = dict(os.environ, EXE2MAC_DIRECT="1")
        r = subprocess.run([str(self.app / "Contents" / "MacOS" / "hello")], capture_output=True, env=env, timeout=60)
        with open(GOLDEN, "rb") as f:
            self.assertEqual(r.stdout, f.read())
        self.assertEqual(r.stderr, b"")
        self.assertEqual(r.returncode, 7)

    def test_guest_binary_is_the_built_executable(self):
        with open(self.res["binary"], "rb") as a, open(self.app / "Contents" / "MacOS" / "hello-guest", "rb") as b:
            self.assertEqual(a.read(), b.read())

    @unittest.skipUnless(ON_MAC, "macOS only")
    def test_macos_signature_and_dmg(self):
        self.assertTrue(self.res["signed"])
        r = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(self.app)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        dmg = self.res["dmg"]
        self.assertIsNotNone(dmg)
        r = subprocess.run(["hdiutil", "imageinfo", str(dmg)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("UDZO", r.stdout)

    def test_doctor_reports_core_prerequisites(self):
        from recompiler.package import doctor
        names = {n: ok for n, ok, _ in doctor()}
        self.assertTrue(names["capstone"])
        self.assertTrue(names["C11 compiler with __int128"])


if __name__ == "__main__":
    unittest.main()
