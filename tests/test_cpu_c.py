"""Compile and run the C runtime semantic tests.

* tests/c/test_cpu.c  - portable, SDM-derived expected values (any host).
* tests/c/diff_x86.c  - differential test against the real CPU; only meaningful
                        on an x86-64 host (exits 77 = skip elsewhere).
Sanitizers (ASan + UBSan) are used when the toolchain provides them.
"""
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
CC = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
RUNTIME = [os.path.join(ROOT, "runtime", f) for f in ("guest_mem.c", "fault.c")]
SAN = ["-fsanitize=undefined,address", "-fno-sanitize-recover=all"]


def _build(src, out, extra):
    cmd = [CC, "-std=gnu11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
           "-ffp-contract=off", "-I", ROOT, *extra, os.path.join(ROOT, "tests", "c", src), *RUNTIME,
           "-lm", "-o", out]
    return subprocess.run(cmd, capture_output=True, text=True)


def _build_best(src, out, extra=()):
    r = _build(src, out, [*extra, *SAN])
    if r.returncode != 0:          # toolchain without sanitizer runtimes
        r = _build(src, out, list(extra))
    return r


@unittest.skipUnless(CC, "a C compiler is required")
class CRuntimeSemanticsTests(unittest.TestCase):
    def test_portable_cpu_and_memory_unit_tests(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "test_cpu")
            r = _build_best("test_cpu.c", exe)
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    @unittest.skipUnless(platform.machine().lower() in ("x86_64", "amd64"),
                         "differential oracle needs an x86-64 host CPU")
    def test_differential_against_host_x86_cpu(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "diff_x86")
            r = _build_best("diff_x86.c", exe, ["-mno-red-zone"])
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=600)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    def test_portable_sse_unit_tests(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "test_sse")
            r = _build_best("test_sse.c", exe)
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    @unittest.skipUnless(platform.machine().lower() in ("x86_64", "amd64"),
                         "differential oracle needs an x86-64 host CPU")
    def test_sse_differential_against_host_x86_cpu(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "diff_sse")
            r = _build_best("diff_sse.c", exe, ["-mno-red-zone"])
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=600)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    def test_guest_heap_and_command_line_quoting(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "test_heap")
            extra = ["-I", os.path.join(ROOT, "runtime"),
                     os.path.join(ROOT, "runtime", "process.c"), os.path.join(ROOT, "runtime", "guest_heap.c")]
            r = _build_best("test_heap.c", exe, extra)
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    def test_portable_packed_sse_unit_tests(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "test_simd")
            r = _build_best("test_simd.c", exe)
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    @unittest.skipUnless(platform.machine().lower() in ("x86_64", "amd64"),
                         "differential oracle needs an x86-64 host CPU")
    def test_packed_sse_differential_against_host_x86_cpu(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "diff_simd")
            r = _build_best("diff_simd.c", exe, ["-mno-red-zone"])
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=900)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    def test_portable_mxcsr_vectors_recorded_from_hardware(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "test_mxcsr")
            r = _build_best("test_mxcsr.c", exe, ["-I", os.path.join(ROOT, "tests", "c")])
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    @unittest.skipUnless(platform.machine().lower() in ("x86_64", "amd64"),
                         "differential oracle needs an x86-64 host CPU")
    def test_mxcsr_differential_all_rounding_ftz_daz_settings(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "diff_mxcsr")
            r = _build_best("diff_mxcsr.c", exe, ["-mno-red-zone"])
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=1800)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)

    @unittest.skipUnless(platform.machine().lower() in ("x86_64", "amd64") and sys.platform.startswith("linux"),
                         "unmasked-exception oracle needs an x86-64 Linux host (SIGFPE + ucontext MXCSR)")
    def test_unmasked_exception_differential(self):
        with tempfile.TemporaryDirectory() as td:
            exe = os.path.join(td, "diff_xm")
            r = _build("diff_xm.c", exe, ["-mno-red-zone"])     # no sanitizers: longjmp out of a signal handler
            self.assertEqual(r.returncode, 0, r.stderr)
            run = subprocess.run([exe], capture_output=True, text=True, timeout=900)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("failures=0", run.stdout)


if __name__ == "__main__":
    unittest.main()
