"""End-to-end: translate test/hello.exe, build a native executable on this
host, EXECUTE it, and compare stdout byte-for-byte and the exit status.

This is an integration test of the generated program on the *current host*.
It is evidence for macOS ARM64 only when this suite is run on macOS ARM64.
"""
import os
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from recompiler import decoder as dec

ROOT = os.path.dirname(os.path.dirname(__file__))
EXE = os.path.join(ROOT, "test", "hello.exe")
GOLDEN = os.path.join(ROOT, "test", "golden", "hello.stdout")
CC = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
EXPECTED_EXIT = 7          # hello.c: ExitProcess(7)


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class HelloEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from recompiler.translate import build
        cls.td = tempfile.TemporaryDirectory()
        cls.binary = build(EXE, os.path.join(cls.td.name, "hello"))
        cls.c_path = cls.binary.with_suffix(".gen.c")
        with open(GOLDEN, "rb") as f:
            cls.golden = f.read()

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def run_binary(self, env_extra=None):
        env = dict(os.environ)
        env.update(env_extra or {})
        return subprocess.run([str(self.binary)], capture_output=True, env=env, timeout=60)

    def test_stdout_matches_golden_byte_for_byte_and_exit_code(self):
        res = self.run_binary()
        self.assertEqual(res.stdout, self.golden)
        self.assertEqual(res.stderr, b"")
        self.assertEqual(res.returncode, EXPECTED_EXIT)

    def test_rebased_image_uses_relocations(self):
        res = self.run_binary({"EXE2MAC_IMAGE_BASE": "7ff6a0000000"})
        self.assertEqual(res.stdout, self.golden)
        self.assertEqual(res.returncode, EXPECTED_EXIT)

    def test_rebased_without_relocations_faults(self):
        """Negative control: drop the relocation table and rebase -> names[]
        still points at the preferred base, which is unmapped -> access violation."""
        src = self.c_path.read_text()
        src, n = re.subn(r"const unsigned exe2mac_nrelocs = \d+u;", "const unsigned exe2mac_nrelocs = 0u;", src)
        self.assertEqual(n, 1)
        from recompiler.translate import compile_c
        c2 = os.path.join(self.td.name, "norelocs.gen.c")
        out2 = os.path.join(self.td.name, "norelocs")
        with open(c2, "w") as f:
            f.write(src)
        compile_c(c2, out2)
        env = dict(os.environ, EXE2MAC_IMAGE_BASE="7ff6a0000000")
        res = subprocess.run([out2], capture_output=True, env=env, timeout=60)
        self.assertEqual(res.returncode, 0x05)                  # STATUS_ACCESS_VIOLATION & 0xff
        self.assertIn(b"invalid guest read", res.stderr)
        # same binary at the preferred base needs no relocation and still works
        res = subprocess.run([out2], capture_output=True, timeout=60)
        self.assertEqual(res.stdout, self.golden)

    def test_invalid_load_bases_are_rejected(self):
        for base in ("140001000", "10000000"):                  # misaligned; overlaps guest stack
            res = self.run_binary({"EXE2MAC_IMAGE_BASE": base})
            self.assertEqual(res.returncode, 125, base)
            self.assertEqual(res.stdout, b"")

    def test_generation_is_deterministic(self):
        from recompiler.translate import translate
        self.assertEqual(translate(EXE), self.c_path.read_text())

    def test_every_reachable_instruction_is_lifted(self):
        from recompiler.cfg import discover
        from recompiler.pe import PE
        prog = discover(PE(EXE))
        src = self.c_path.read_text()
        for va in prog.instructions:
            self.assertIn(f"/* 0x{va:x}: ", src)

    def test_cli_run_reports_match(self):
        res = subprocess.run(["python3", "-m", "recompiler", "run", EXE,
                              "--expect-stdout", GOLDEN, "--expect-exit", str(EXPECTED_EXIT)],
                             cwd=ROOT, capture_output=True, timeout=300)
        self.assertEqual(res.returncode, 0, res.stderr.decode(errors="replace"))
        self.assertIn(b"byte-for-byte", res.stderr)
        self.assertIn(b"MATCH", res.stderr)
        self.assertNotIn(b"MISMATCH", res.stderr)

    def test_report_host(self):
        # Recorded in the test log so results can't be mistaken for another platform's.
        print(f"\n[e2e host] {platform.system()} {platform.machine()}", end="")


@unittest.skipUnless(shutil.which("clang") and dec.capstone is not None, "clang and capstone required")
class MacOSArm64CompileOnlyTests(unittest.TestCase):
    """COMPILE-ONLY check that the generated C targets arm64-apple-macos.
    It neither links nor runs anything and is not evidence of runtime behaviour."""

    def test_generated_c_compiles_to_arm64_macho_object(self):
        probe = subprocess.run(["clang", "-target", "arm64-apple-macos11", "-ffreestanding", "-x", "c",
                                "-c", "-", "-o", os.devnull], input=b"int x;", capture_output=True)
        if probe.returncode:
            self.skipTest("clang lacks the arm64-apple-macos target")
        from recompiler.translate import translate
        with tempfile.TemporaryDirectory() as td:
            c = os.path.join(td, "hello.gen.c")
            o = os.path.join(td, "hello.gen.o")
            with open(c, "w") as f:
                f.write(translate(EXE))
            r = subprocess.run(["clang", "-target", "arm64-apple-macos11", "-ffreestanding", "-std=c11", "-O2",
                                "-Wall", "-Wextra", "-Werror", "-I", ROOT, "-I", os.path.join(ROOT, "runtime"),
                                "-c", c, "-o", o], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(o, "rb") as f:
                hdr = f.read(8)
        self.assertEqual(hdr[:4], bytes.fromhex("cffaedfe"))      # MH_MAGIC_64, little-endian
        self.assertEqual(hdr[4:8], bytes.fromhex("0c000001"))     # CPU_TYPE_ARM64


if __name__ == "__main__":
    unittest.main()
