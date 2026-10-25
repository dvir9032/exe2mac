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


class _FixtureE2E:
    """Translate, build, EXECUTE a fixture; compare stdout and exit code with a
    golden file produced by an independent model (test/golden/<name>_model.py)
    and confirmed by the Windows reference job in CI."""

    NAME = None
    EXIT = None
    ARGS = ()          # extra host argv -> Windows command line
    STDIN = None       # file under test/golden fed to standard input

    @property
    def EXE(self):
        return os.path.join(ROOT, "test", f"{self.NAME}.exe")

    @property
    def GOLDEN(self):
        return os.path.join(ROOT, "test", "golden", f"{self.NAME}.stdout")

    def test_stdout_and_exit_code(self):
        from recompiler.translate import build
        with tempfile.TemporaryDirectory() as td:
            exe = build(self.EXE, os.path.join(td, self.NAME))
            stdin = b""
            if self.STDIN:
                with open(os.path.join(ROOT, "test", "golden", self.STDIN), "rb") as f:
                    stdin = f.read()
            argv = [str(exe), *self.ARGS]
            res = subprocess.run(argv, capture_output=True, timeout=60, input=stdin)
            res2 = subprocess.run(argv, capture_output=True, timeout=60, input=stdin,
                                  env=dict(os.environ, EXE2MAC_IMAGE_BASE="7ff6a0000000"))
        with open(self.GOLDEN, "rb") as f:
            golden = f.read()
        self.assertEqual(res.stdout, golden)
        self.assertEqual(res.stderr, b"")
        self.assertEqual(res.returncode, self.EXIT)
        self.assertEqual(res2.stdout, golden)
        self.assertEqual(res2.returncode, self.EXIT)

    def test_model_reproduces_golden(self):
        res = subprocess.run(["python3", "-I", os.path.join(ROOT, "test", "golden", f"{self.NAME}_model.py")],
                             capture_output=True, timeout=60)
        with open(self.GOLDEN, "rb") as f:
            self.assertEqual(res.stdout, f.read())
        self.assertIn(f"exit={self.EXIT}".encode(), res.stderr)


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class OpsEndToEndTests(_FixtureE2E, unittest.TestCase):
    """test/ops.c: movzx/movsx, shl/sar, div, setcc, adc/sbb, not, xchg, rep stosb/movsb, movaps."""
    NAME, EXIT = "ops", 102


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class SwitchEndToEndTests(_FixtureE2E, unittest.TestCase):
    """test/switch.c: dense switches compiled to jump tables, plus a sparse compare tree."""
    NAME, EXIT = "switch", 50


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class FpEndToEndTests(_FixtureE2E, unittest.TestCase):
    """test/fp.c: scalar SSE double/float arithmetic, sqrt, min/max, compares,
    conversions; results printed as exact IEEE-754 bit patterns."""
    NAME, EXIT = "fp", 27


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class IoEndToEndTests(_FixtureE2E, unittest.TestCase):
    """test/io.c (built with default -O2, i.e. auto-vectorised): ReadFile(stdin),
    GetCommandLineA, process heap, VirtualAlloc, GetLastError/SetLastError.
    Same arguments and input as test/io.windows.bat."""
    NAME, EXIT = "io", 5
    ARGS = ("alpha", "b c", 'q"uote', "back\\slash\\", "")
    STDIN = "io.input"


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class VecEndToEndTests(_FixtureE2E, unittest.TestCase):
    """test/vec.c: loops auto-vectorised by clang -O2 (packed SSE2 integer and FP)."""
    NAME, EXIT = "vec", 42


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class TailEndToEndTests(_FixtureE2E, unittest.TestCase):
    """test/tail.c: direct mutual tail recursion and an indirect tail-call state
    machine, each one million levels deep (host stack must not grow), plus tail
    calls into imports including the no-return ExitProcess."""
    NAME, EXIT = "tail", 13

    def test_strict_mode_rejects_the_indirect_tail_calls(self):
        from recompiler.translate import TranslationError, translate
        with self.assertRaisesRegex(TranslationError, "unresolved indirect jump"):
            translate(self.EXE, strict_indirect_jumps=True)


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
