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
RUNTIME = ["loader.c", "dispatch.c", "winapi_bridge.c", "winapi_shims.c", "process.c", "guest_heap.c",
           "guest_mem.c", "fault.c"]

REGS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
STACK_TOP = 0x10000000 + 0x100000
RSP0 = STACK_TOP - 0x28


def build_snippet(code_hex, td, imports=(), rdata=b"", data=b""):
    from recompiler.lift_c import Lifter
    from recompiler.cfg import discover
    pe = FakePE(bytes.fromhex(code_hex), rdata=rdata, imports=imports, data=data)
    c = os.path.join(td, "snip.gen.c")
    exe = os.path.join(td, "snip")
    with open(c, "w") as f:
        f.write(Lifter(pe, discover(pe)).emit())
    cmd = [CC, "-std=c11", "-D_DEFAULT_SOURCE", "-O1", "-Wall", "-Wextra", "-Werror", "-ffp-contract=off",
           "-I", ROOT, "-I", os.path.join(ROOT, "runtime"), c,
           os.path.join(ROOT, "tests", "c", "snippet_main.c"),
           *[os.path.join(ROOT, "runtime", r) for r in RUNTIME], "-lm", "-o", exe]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise AssertionError(r.stderr)
    return exe


def snippet_exit_status(code_hex, data=b""):
    with tempfile.TemporaryDirectory() as td:
        exe = build_snippet(code_hex, td, data=data)
        return subprocess.run([exe], capture_output=True, timeout=30)


def run_snippet(code_hex, imports=(), rdata=b""):
    with tempfile.TemporaryDirectory() as td:
        exe = build_snippet(code_hex, td, imports=imports, rdata=rdata)
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


class _SnippetCheck:
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



@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class LiftedSnippetTests(_SnippetCheck, unittest.TestCase):
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


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class LiftedSnippetTestsWave2(_SnippetCheck, unittest.TestCase):
    """Forms added for test/ops.exe: movzx/movsx, shl/sar, setcc, adc/sbb, not,
    div, xchg with memory, rep stosb/movsb, movaps."""

    def test_zero_and_sign_extension(self):
        code = ("48c7c0ffffffffb9f08000000fb6c148c7c2ffffffff0fbed1480fbfd90fb7f10fb6ed4883ec08"
                "66c70424feff4c0fbf0c24440fb65424014883c408c3")
        t = texts(code)
        for want in ("movzx eax, cl", "movsx edx, cl", "movsx rbx, cx", "movzx esi, cx", "movzx ebp, ch",
                     "movsx r9, word ptr [rsp]", "movzx r10d, byte ptr [rsp + 1]"):
            self.assertIn(want, t)
        self.check(code, {"rax": 0xF0, "rcx": 0x80F0,
                          "rdx": 0xFFFFFFF0,                # movsx to 32-bit zero-extends to 64
                          "rbx": 0xFFFFFFFFFFFF80F0, "rsi": 0x80F0, "rbp": 0x80,
                          "r9": -2, "r10": 0xFF},
                   {"cf": 0, "pf": 1, "af": 0, "zf": 0, "sf": 0, "of": 0})

    def test_shifts_setcc_carry_chain_and_not(self):
        code = ("48b80100000000000080b14148d3e048c7c3f9ffffff48d1fb48c7c2ffffffff0f92c248c7c6ffffffff"
                "4883c60148c7c7050000004883d70049c7c0000000004983e80149c7c10a0000004983d90349c7c2ff000000"
                "49f7d2410f95c3c3")
        t = texts(code)
        for want in ("shl rax, cl", "sar rbx, 1", "setb dl", "adc rdi, 0", "sbb r9, 3", "not r10", "setne r11b"):
            self.assertIn(want, t)
        self.check(code, {"rax": 2,                         # 0x8000000000000001 << (65 & 63)
                          "rcx": 65, "rbx": -4,             # -7 >> 1 rounds toward -inf
                          "rdx": 0xFFFFFFFFFFFFFF01,        # setb dl after sar's CF=1
                          "rsi": 0, "rdi": 6,               # adc consumes CF from add
                          "r8": -1, "r9": 6,                # sbb consumes CF from sub
                          "r10": 0xFFFFFFFFFFFFFF00, "r11": 1},
                   {"cf": 0, "pf": 1, "af": 0, "zf": 0, "sf": 0, "of": 0})   # from sbb; not/setcc keep flags

    def test_div_xchg_string_ops_and_movaps(self):
        code = ("48c7c007ca9a3b31d248c7c10a00000048f7f148c7c3111100004883ec4848c704242222000048871c24"
                "4c8b2424488d7c2408b910000000b841000000f3aa488d742408488d7c2420b903000000f3a44c8b6c2420"
                "0f284424100f28c80f294c24304c8b7424304c8b7c24384883c448c3")
        t = texts(code)
        for want in ("div rcx", "xchg qword ptr [rsp], rbx", "rep stosb byte ptr [rdi], al",
                     "rep movsb byte ptr [rdi], byte ptr [rsi]", "movaps xmm0, xmmword ptr [rsp + 0x10]",
                     "movaps xmm1, xmm0", "movaps xmmword ptr [rsp + 0x30], xmm1"):
            self.assertIn(want, t)
        frame = RSP0 - 0x48
        self.check(code, {"rax": 0x41, "rdx": 7, "rcx": 0,
                          "rbx": 0x2222, "r12": 0x1111,
                          "rdi": frame + 0x23, "rsi": frame + 0x0B,
                          "r13": 0x414141,                  # 3 bytes copied by rep movsb
                          "r14": 0x4141414141414141, "r15": 0},
                   {"cf": 0, "pf": 1, "af": 0, "zf": 0, "sf": 0, "of": 0})

    def test_misaligned_movaps_faults(self):
        r = snippet_exit_status("4883ec080f284424084883c408c3")
        self.assertEqual(r.returncode, 0x05)               # STATUS_ACCESS_VIOLATION & 0xff
        self.assertIn(b"misaligned", r.stderr)

    def test_unsigned_divide_by_zero_faults(self):
        r = snippet_exit_status("31c931d2b801000000f7f1c3")
        self.assertEqual(r.returncode, 0x94)               # STATUS_INTEGER_DIVIDE_BY_ZERO & 0xff
        self.assertIn(b"div32: divide by zero", r.stderr)


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class LiftedSSETests(_SnippetCheck, unittest.TestCase):
    """Scalar SSE: which part of the destination register each form writes."""

    UPPER = ("4883ec2848b800000000000000404889042448b8aaaaaaaaaaaaaaaa48894424080f280424f20f100c24"
             "48b8000000000000f03f66480f6ed0f20f58c20f28d8f20f10da0f28e0f20f51e10f28e8b9f9fffffff20f2ae9"
             "f2440f2cc50f28f0f20f5af2660f2ed10f92c2400f94c766490f7ec10f294424104c8b54241866490f7edb"
             "66490f7ee466490f7eed66490f7ef666410f7ef766480f7ecb0f294c2410488b7424184883c428c3")

    def test_scalar_writes_preserve_or_zero_the_upper_half(self):
        t = texts(self.UPPER)
        for want in ("movsd xmm1, qword ptr [rsp]", "addsd xmm0, xmm2", "movsd xmm3, xmm2", "sqrtsd xmm4, xmm1",
                     "cvtsi2sd xmm5, ecx", "cvttsd2si r8d, xmm5", "cvtsd2ss xmm6, xmm2", "ucomisd xmm2, xmm1",
                     "movd r15d, xmm6", "movq r9, xmm0"):
            self.assertIn(want, t)
        self.check(self.UPPER, {
            "rax": 0x3FF0000000000000,
            "rdx": 1,                        # setb after ucomisd 1.0 vs 2.0 (CF=1)
            "rdi": 0,                        # sete: ZF=0
            "rcx": 0xFFFFFFF9, "r8": 0xFFFFFFF9,       # cvttsd2si r32 zero-extends
            "r9": 0x4008000000000000,        # 2.0 + 1.0
            "r10": 0xAAAAAAAAAAAAAAAA,       # addsd kept xmm0's high qword
            "r11": 0x3FF0000000000000,       # movsd xmm, xmm merges only the low qword
            "r12": 0x3FF6A09E667F3BCD,       # sqrt(2.0)
            "r13": 0xC01C000000000000,       # cvtsi2sd(-7)
            "r14": 0x400800003F800000,       # cvtsd2ss writes only bits 0..31
            "r15": 0x3F800000,
            "rbx": 0x4000000000000000,
            "rsi": 0,                        # movsd xmm, m64 zeroed the high qword
        }, {"cf": 0, "pf": 1, "af": 0, "zf": 0, "sf": 0, "of": 0})   # from the final `add rsp, 0x28`

    def test_unaligned_movups_is_allowed(self):
        self.check("4883ec2848c7442408050000000f1044240866480f7ec04883c428c3", {"rax": 5},
                   {"cf": 0, "pf": 1, "af": 0, "zf": 0, "sf": 0, "of": 0})

    def test_misaligned_legacy_sse_memory_operand_faults(self):
        r = snippet_exit_status("4883ec080f574424084883c408c3")        # xorps xmm0, [rsp+8]
        self.assertEqual(r.returncode, 0x05)
        self.assertIn(b"misaligned 128-bit operand", r.stderr)

    def test_fp_fixture_end_to_end_lives_in_test_e2e(self):
        self.assertTrue(os.path.exists(os.path.join(ROOT, "test", "fp.exe")))


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class LiftedPackedSSETests(_SnippetCheck, unittest.TestCase):
    """Packed SSE2 integer forms; expected values derived by hand from the SDM."""

    PACKED = ("4883ec2848b80201fe007f01ff804889042448b8efcdab89674523014889442408660f6f0424660f74c9"
              "660f6fd0660ffcd148c7c3ffffffff660fd7d866490f7ed0660f73d00466490f7ec1b802000000660f6ee0"
              "660f6f2c24660ff3ec66490f7eea660f7034244e66490f7ef3660f6f3c24660f67ff66490f7efc4883c428c3")

    def test_packed_integer_forms(self):
        t = texts(self.PACKED)
        for want in ("pcmpeqb xmm1, xmm1", "paddb xmm2, xmm1", "pmovmskb ebx, xmm0", "psrlq xmm0, 4",
                     "psllq xmm5, xmm4", "pshufd xmm6, xmmword ptr [rsp], 0x4e", "packuswb xmm7, xmm7"):
            self.assertIn(want, t)
        self.check(self.PACKED, {
            "rax": 2,
            "rbx": 0xFC4,                    # sign bits of the 16 bytes; 32-bit write zero-extends
            "r8": 0x7FFE007EFFFD0001,        # every byte - 1 (paddb with all-ones)
            "r9": 0x080FF017F00FE010,        # psrlq by 4
            "r10": 0x03FC05FC03F80408,       # psllq by the count in xmm4 (2)
            "r11": 0x0123456789ABCDEF,       # pshufd 0x4e swaps the qwords
            "r12": 0xFFFF000000FFFEFF,       # packuswb: signed words saturated to unsigned bytes
        }, {"cf": 0, "pf": 1, "af": 0, "zf": 0, "sf": 0, "of": 0})

    def test_misaligned_packed_memory_operand_faults(self):
        r = snippet_exit_status("4883ec08660ffc4424084883c408c3")   # paddb xmm0, [rsp+8]
        self.assertEqual(r.returncode, 0x05)
        self.assertIn(b"misaligned 128-bit operand", r.stderr)


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
        self.assertRejected("480fa308c3", "memory bit string")                  # bt [rax], rcx
        self.assertRejected("48d1c0c3", "unsupported instruction.*rol")          # rol rax, 1
        self.assertRejected("0f5dc1c3", "register xmm0 is not supported")       # minps (not implemented)

    def test_unsupported_sse(self):
        self.assertRejected("f20f2dc0c3", "register xmm0 is not supported")      # cvtsd2si (rounding mode)
        self.assertRejected("660ff5c1c3", "register xmm0 is not supported")      # pmaddwd (not implemented)
        self.assertRejected("0fae1424c3", "unsupported instruction.*ldmxcsr")    # MXCSR changes

    def test_rep_prefix(self):
        self.assertRejected("f3abc3", "REP")                                     # rep stosd (only stosb/movsb)
        self.assertRejected("f2aec3", "REP")                                     # repne scasb

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
