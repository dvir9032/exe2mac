"""Compile and run the Windows x64 ABI bridge tests (tests/c/test_bridge.c)."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
CC = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
SRCS = ["dispatch.c", "winapi_bridge.c", "winapi_shims.c", "guest_mem.c", "fault.c"]


@unittest.skipUnless(CC, "a C compiler is required")
class BridgeTests(unittest.TestCase):
    def test_bridges(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "test_bridge")
            base = [CC, "-std=c11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
                    "-I", ROOT, "-I", os.path.join(ROOT, "runtime"),
                    os.path.join(ROOT, "tests", "c", "test_bridge.c"),
                    *[os.path.join(ROOT, "runtime", x) for x in SRCS], "-o", exe]
            r = subprocess.run(base[:1] + ["-fsanitize=undefined,address", "-fno-sanitize-recover=all"] + base[1:],
                               capture_output=True, text=True)
            if r.returncode:
                r = subprocess.run(base, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(run.stdout, b"bridge-ok\n")
        self.assertIn(b"failures=0", run.stderr)


if __name__ == "__main__":
    unittest.main()
