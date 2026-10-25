"""Lifter tests: translated snippets are compiled, executed, and their final
guest state is compared with values derived from the Intel SDM by hand.

Snippet bytes were assembled with GNU as (Intel syntax); each test also checks
the decoded text so the bytes and the intent cannot drift apart.
"""
import os
import shutil
import subprocess
import tempfile
import unittest

import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recompiler import decoder as dec  # noqa: E402
from fake_pe import BASE, FakePE  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(__file__))
CC = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
RUNTIME = ["loader.c", "dispatch.c", "winapi_bridge.c", "winapi_shims.c", "guest_mem.c", "fault.c"]

REGS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
STACK_TOP = 0x10000000 + 0x100000
RSP0 = STACK_TOP - 0x28


def run_snippet(code_hex, imports=(), rdata=b""):
    from recompiler.lift_c import Lifter
    from recompiler.cfg import discover
    pe = FakePE(bytes.fromhex(code_hex), rdata=rdata, imports=imports)
    c_src = Lifter(pe, discover(pe)).emit()
    with tempfile.TemporaryDirectory() as td:
        c = os.path.join(td, "snip.gen.c")
        exe = os.path.join(td, "snip")
        with open(c, "w") as f:
            f.write(c_src)
        cmd = [CC, "-std=c11", "-D_DEFAULT_SOURCE", "-O1", "-Wall", "-Wextra", "-Werror",
               "-I", ROOT, "-I", os.path.join(ROOT, "runtime"), c,
               os.path.join(ROOT, "tests", "c", "snippet_main.c"),
               *[os.path.join(ROOT, "runtime", r) for r in RUNTIME], "-o", exe]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            raise AssertionError(r.stderr)
        run = subprocess.run([exe], capture_output=True, text=True, timeout=30)
    if run.returncode:
        raise AssertionError(f"snippet exited {run.returncode}: {run.stderr}")
    state = {}
    for line in run.stdout.splitlines():
        for item in line.split():
            k, v = item.split("=")
            state[k] = int(v, 10) if k in ("cf", "pf", "af", "zf", "sf", "of", "rsp_delta") else int(v, 16)
    return state


def texts(code_hex):
    return [i.text for i in dec.decode_linear(bytes.fromhex(code_hex), BASE + 0x1000)]


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class LiftedSnippetTests(unittest.TestCase):
    def check(self, code_hex, expect_regs, expect_flags=None):
        st = run_snippet(code_hex)
        self.assertEqual(st["rsp_delta"], 8)          # entry RET popped the sentinel
        for r in REGS:
            if r == "rsp":
                continue
            self.assertEqual(st[r], expect_regs.get(r, 0) & (2**64 - 1), f"{r}: got 0x{st[r]:x}")
        if expect_flags:
            for k, v in expect_flags.items():
                self.assertEqual(st[k], v, k)

    def test_partial_register_writes(self):
        code = "48c7c0ffffffffb80500000048c7c3ffffffffb31248c7c1ffffffff66b90700ba3412000088f449c7c0ffffffff41b080c3"
        self.assertIn("mov ah, dh", texts(code))
        self.check(code, {"rax": 0x1205,                    # mov eax,5 zero-extends; then AH <- DH
                          "rbx": 0xFFFFFFFFFFFFFF12,        # BL write merges
                          "rcx": 0xFFFFFFFFFFFF0007,        # CX write merges
                          "rdx": 0x1234,
                          "r8": 0xFFFFFFFFFFFFFF80},        # R8B write merges
                   {"cf": 0, "pf": 0, "af": 0, "zf": 0, "sf": 0, "of": 0})

    def test_cmov_32bit_not_taken_still_zero_extends(self):
        code = "48c7c2ffffffff31c00f48d049c7c1ffffffff41ba030000004585d24d0f49cac3"
        self.assertEqual(texts(code)[2], "cmovs edx, eax")
        self.check(code, {"rdx": 0xFFFFFFFF, "r9": 3, "r10": 3},
                   {"cf": 0, "pf": 1, "zf": 0, "sf": 0, "of": 0})

    def test_memory_read_modify_write_and_sib(self):
        code = ("4883ec1048c704240500000048830424f9c744240800000000ff4c2408488b04248b5c2408"
                "c64404032d" "8a4c2401" "4883c410c3")
        self.assertIn("add qword ptr [rsp], -7", texts(code))
        self.assertIn("dec dword ptr [rsp + 8]", texts(code))
        self.check(code, {"rax": -2, "rbx": 0xFFFFFFFF, "rcx": 0x2D},
                   # flags of final `add rsp, 0x10`: 0x100fffc8 + 0x10 = 0x100fffd8
                   {"cf": 0, "pf": 1, "af": 0, "zf": 0, "sf": 0, "of": 0})

    def test_push_pop_including_push_rsp_and_sign_extended_immediates(self):
        code = "4889e3545968ffffff7f5a6afe5ec3"
        self.assertEqual(texts(code)[1:3], ["push rsp", "pop rcx"])
        self.check(code, {"rbx": RSP0, "rcx": RSP0, "rdx": 0x7FFFFFFF, "rsi": -2})

    def test_lea_truncation_and_scaled_index(self):
        code = "48ba01000000010000008d04124c8d04d5fcffffff448d4afec3"
        self.check(code, {"rdx": 0x100000001, "rax": 2, "r8": 0x800000004, "r9": 0xFFFFFFFF})

    def test_arithmetic_used_by_fixture(self):
        code = ("b94100000048c7c01000000048d3e84889c348b8cdcccccccccccccc48c7c1d204000048f7e1"
                "48c1ea034989d2b85400000041b8fcffffff9941f7f84989c341bc54000000450fafe0b900000080"
                "4c63e941beebffffff4589f741f7df450f48fec3")
        t = texts(code)
        for want in ("shr rax, cl", "mul rcx", "cdq", "idiv r8d", "imul r12d, r8d", "movsxd r13, ecx", "cmovs r15d, r14d"):
            self.assertIn(want, t)
        self.check(code, {"rbx": 8,                         # 0x10 >> (65 & 63)
                          "r10": 123,                       # 1234 / 10 via reciprocal multiply
                          "rax": 0xFFFFFFEB, "rdx": 0,      # 84 / -4 = -21 r 0
                          "r11": 0xFFFFFFEB,
                          "r8": 0xFFFFFFFC,
                          "r12": 0xFFFFFEB0,                # 84 * -4 = -336
                          "rcx": 0x80000000,
                          "r13": 0xFFFFFFFF80000000,
                          "r14": 0xFFFFFFEB,
                          "r15": 21},                       # abs(-21) via neg + cmovs
                   # flags from `neg r15d` with r15d = -21
                   {"cf": 1, "pf": 0, "af": 1, "zf": 0, "sf": 0, "of": 0})


@unittest.skipUnless(dec.capstone is not None, "capstone required")
class FailClosedLifterTests(unittest.TestCase):
    def lift(self, code_hex, **kw):
        from recompiler.lift_c import Lifter
        from recompiler.cfg import discover
        pe = FakePE(bytes.fromhex(code_hex), **kw)
        return Lifter(pe, discover(pe)).emit()

    def assertRejected(self, code_hex, pattern, **kw):
        from recompiler.lift_c import TranslationError
        with self.assertRaisesRegex(TranslationError, pattern):
            self.lift(code_hex, **kw)

    def test_unsupported_instruction(self):
        self.assertRejected("0fb64c2401c3", "unsupported instruction.*movzx")    # movzx ecx, byte [rsp+1]
        self.assertRejected("4893c3", "unsupported instruction.*xchg")           # xchg rbx, rax
        self.assertRejected("48d1e0c3", "unsupported instruction.*shl")          # shl rax, 1

    def test_rep_prefix(self):
        self.assertRejected("f3aac3", "REP")                                     # rep stosb

    def test_ret_imm(self):
        self.assertRejected("c20800", "ret imm16")

    def test_segment_override(self):
        self.assertRejected("64488b042530000000c3", "segment override fs")     # mov rax, fs:[0x30]

    def test_one_operand_imul(self):
        self.assertRejected("48f7e9c3", "one-operand imul")

    def test_unsupported_import(self):
        self.assertRejected("c3", "unsupported import kernel32.dll!GetTickCount",
                            imports=[(0x2000, "kernel32.dll", "GetTickCount")])

    def test_relocation_inside_code(self):
        from recompiler.lift_c import TranslationError
        from recompiler.lift_c import Lifter
        from recompiler.cfg import discover
        pe = FakePE(bytes.fromhex("48b80000004001000000c3"))                    # movabs rax, imm64
        pe.relocs = [0x1002]
        with self.assertRaisesRegex(TranslationError, "relocation at RVA 0x1002 patches code"):
            Lifter(pe, discover(pe)).emit()

    def test_generated_code_never_contains_fallback_noop(self):
        src = self.lift("4831c0c3")                                              # xor rax, rax ; ret
        self.assertIn("x86_xor", src)
        self.assertNotIn("TODO", src)


if __name__ == "__main__":
    unittest.main()
