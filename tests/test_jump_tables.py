"""Jump-table (bounded `switch`) recognition, lifting and fail-closed cases.

Snippets were assembled with GNU as; tables use `.long target - table`, the
relative-offset form clang emits for Windows x64."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recompiler import decoder as dec  # noqa: E402
from fake_pe import BASE, DATA_RVA, TEXT_RVA, FakePE  # noqa: E402
from test_lifter import CC, RSP0, _SnippetCheck, snippet_exit_status  # noqa: E402,F401

ROOT = os.path.dirname(os.path.dirname(__file__))

JT_OK = ("b902000000e8110000004889c3b909000000e8040000004889c6c383f903772a89c8488d152b000000"
         "486304824801d0ffe0b864000000c3b865000000c3b866000000c3b867000000c331d2b8e7030000c3"
         "6690deffffffe4ffffffeafffffff0ffffff")
JT_NOBOUND = "89c8488d150b000000486304824801d0ffe0c390feffffff"
JT_BYPASS = "85c9780583f900771389c8488d150e000000486304824801d0ffe0c3c30f1f00fbffffff"
JT_NOZEXT = "83f9007711488d150c0000004863048a4801d0ffe0c3c390fdffffff"
# Zero-extension proved by an earlier 32-bit write: `mov ebx, 2; call f; cmp ebx, 3; ja; ...
# movsxd rax, [rdx+rbx*4]`. RBX is callee-saved, so the call cannot change it.
JT_ZEXT_NV = ("bb02000000e83300000083fb037728488d15280000004863049a4801d0ffe0b864000000c3b865000000c3"
              "b866000000c3b867000000c3b8e7030000c3c3e1ffffffe7ffffffedfffffff3ffffff")
# Same with RCX (volatile: the callee may leave garbage in bits 32..63) -> no proof.
JT_ZEXT_VOL = ("b902000000e83300000083f9037728488d15280000004863048a4801d0ffe0b864000000c3b865000000c3"
               "b866000000c3b867000000c3b8e7030000c3c3e1ffffffe7ffffffedfffffff3ffffff")
# A 64-bit write (`add rbx, 1`) or a high-byte write (`mov bh, 0`) after the 32-bit one -> no proof.
JT_ZEXT_W64 = ("bb02000000e8370000004883c30183fb037728488d15280000004863049a4801d0ffe0b864000000c3"
               "b865000000c3b866000000c3b867000000c3b8e7030000c3c3e1ffffffe7ffffffedfffffff3ffffff")
JT_ZEXT_H8 = ("bb02000000e835000000b70083fb037728488d15280000004863049a4801d0ffe0b864000000c3b865000000c3"
              "b866000000c3b867000000c3b8e7030000c3c3e1ffffffe7ffffffedfffffff3ffffff")
# MSVC: `cmp ecx, 3; ja; movsxd rax, ecx; lea rdx, [__ImageBase];
# mov ecx, [rdx + rax*4 + RVA(tbl)]; add rcx, rdx; jmp rcx` - entries are RVAs.
JT_MSVC = ("bb02000000e83b00000089d983f903772e4863c1488d15e5efffff8b8c82461000004801d1ffe1b864000000c3"
           "b865000000c3b866000000c3b867000000c3b8e7030000c3c3271000002d1000003310000039100000")
# MSVC two-level: byte index table u8[rbx + RVA(idx) + rdi] selects the RVA entry; the image
# base is loaded into RBX (callee-saved) before a call, i.e. before the bounds check.
JT_MSVC2 = ("488d1df9efffffbf05000000e83100000083ff0777260fb6843b4f1000008b8c83431000004801d9ffe1b864000000"
            "c3b865000000c3b866000000c3b8e7030000c3c32a10000030100000361000000000010102020100")
# Same with the base in R9 (volatile): the call may change it -> no table.
JT_MSVC2_VOL = ("4c8d0df9efffffbf05000000e83300000083ff077728410fb6843951100000418b8c81451000004c01c9ffe1b864"
                "000000c3b865000000c3b866000000c3b8e7030000c3c32c10000032100000381000000000010102020100")
JT_RUNTIME = ("31c9488d15000000004c8d05f0ffffff4929d044890283f900771889c8488d1500000000"
              "486304824801d0ffe0b801000000c3c3")


def discover(code_hex, data=b"", strict=False):
    from recompiler.cfg import discover as d
    return d(FakePE(bytes.fromhex(code_hex), data=data), strict_indirect_jumps=strict)


def runtime_snippet():
    """Patch both `lea rdx, [rip+0]` placeholders to address a table in .data,
    whose initial entry points at the `c0` case."""
    code = bytearray(bytes.fromhex(JT_RUNTIME))
    lea = bytes.fromhex("488d1500000000")
    table_va = BASE + DATA_RVA
    pos = 0
    while True:
        pos = code.find(lea, pos)
        if pos < 0:
            break
        disp = table_va - (BASE + TEXT_RVA + pos + 7)
        code[pos + 3:pos + 7] = struct.pack("<i", disp)
        pos += 7
    c0 = code.find(bytes.fromhex("b801000000"))
    data = struct.pack("<i", (BASE + TEXT_RVA + c0) - table_va)
    return code.hex(), data, BASE + TEXT_RVA + c0


@unittest.skipUnless(dec.capstone is not None, "capstone required")
class JumpTableCFGTests(unittest.TestCase):
    def test_fixture_tables(self):
        from recompiler.cfg import discover as d
        from recompiler.pe import PE
        prog = d(PE(os.path.join(ROOT, "test", "switch.exe")))
        tables = sorted((j.count, len(set(j.targets))) for j in prog.jump_tables.values())
        self.assertEqual(tables, [(7, 7), (12, 12)])        # day(): 0..6, op(): 0..11

    def test_synthetic_table_targets(self):
        prog = discover(JT_OK)
        (jt,) = prog.jump_tables.values()
        self.assertEqual(jt.count, 4)                       # cmp ecx, 3 ; ja -> entries 0..3
        insns = prog.instructions
        texts = [insns[t].text for t in jt.targets]
        self.assertEqual(texts, ["mov eax, 0x64", "mov eax, 0x65", "mov eax, 0x66", "mov eax, 0x67"])

    def test_missing_bounds_check_is_rejected(self):
        from recompiler.cfg import CFGError
        with self.assertRaisesRegex(CFGError, "unresolved indirect jump"):
            discover(JT_NOBOUND, strict=True)

    def test_entry_that_bypasses_the_bounds_check_is_rejected(self):
        from recompiler.cfg import CFGError
        with self.assertRaisesRegex(CFGError, "unresolved indirect jump|from outside its bounds check"):
            discover(JT_BYPASS, strict=True)

    def test_unrecognised_tables_become_dynamic_tail_calls_by_default(self):
        for code in (JT_NOBOUND, JT_BYPASS, JT_NOZEXT):
            prog = discover(code)
            self.assertEqual(len(prog.dynamic_tail_jumps), 1)
            self.assertEqual(prog.jump_tables, {})

    def test_zero_extension_proved_by_earlier_32bit_write(self):
        prog = discover(JT_ZEXT_NV, strict=True)
        (jt,) = prog.jump_tables.values()
        self.assertEqual(jt.count, 4)

    def test_zero_extension_proof_fails_closed(self):
        for code in (JT_ZEXT_VOL, JT_ZEXT_W64, JT_ZEXT_H8):
            prog = discover(code)
            self.assertEqual(prog.jump_tables, {})
            self.assertEqual(len(prog.dynamic_tail_jumps), 1)

    def test_msvc_rva_table(self):
        (jt,) = discover(JT_MSVC, strict=True).jump_tables.values()
        self.assertEqual(jt.count, 4)
        self.assertEqual([t - BASE - TEXT_RVA for t in jt.targets], [0x27, 0x2d, 0x33, 0x39])

    def test_msvc_two_level_table_with_base_set_before_the_check(self):
        (jt,) = discover(JT_MSVC2, strict=True).jump_tables.values()
        self.assertEqual(jt.count, 8)                       # entries 0..7 via the byte index table
        self.assertEqual(sorted({t - BASE - TEXT_RVA for t in jt.targets}), [0x2a, 0x30, 0x36])

    def test_base_in_volatile_register_across_call_is_not_a_table(self):
        prog = discover(JT_MSVC2_VOL)
        self.assertEqual(prog.jump_tables, {})
        self.assertEqual(len(prog.dynamic_tail_jumps), 1)

    def test_xm_fixture_table(self):
        from recompiler.cfg import discover as d
        from recompiler.pe import PE
        prog = d(PE(os.path.join(ROOT, "test", "xm.exe")), strict_indirect_jumps=True)
        self.assertEqual([j.count for j in prog.jump_tables.values()], [7])   # `cmovb edi, eax` proves rdi < 2^32

    def test_index_without_zero_extension_is_rejected(self):
        from recompiler.cfg import CFGError
        with self.assertRaisesRegex(CFGError, "unexpected table load"):
            discover(JT_NOZEXT, strict=True)


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class JumpTableExecutionTests(_SnippetCheck, unittest.TestCase):
    def test_msvc_tables_execute(self):
        self.check(JT_MSVC, {"rax": 102, "rbx": 2, "rcx": BASE + TEXT_RVA + 0x33, "rdx": BASE})
        self.check(JT_MSVC2, {"rax": 102, "rbx": BASE, "rcx": BASE + TEXT_RVA + 0x36, "rdi": 5})   # idx[5] = 2

    def test_table_with_zero_extension_proved_earlier(self):
        table = BASE + TEXT_RVA + len(bytes.fromhex(JT_ZEXT_NV)) - 16
        self.check(JT_ZEXT_NV, {"rax": 102, "rbx": 2, "rdx": table})

    def test_in_range_and_default_paths(self):
        self.check(JT_OK, {"rbx": 102, "rsi": 999, "rax": 999, "rcx": 9, "rdx": 0},
                   {"cf": 0, "pf": 1, "af": 0, "zf": 1, "sf": 0, "of": 0})   # from `xor edx, edx`

    def test_unrecognised_table_target_faults_at_run_time(self):
        # default mode: the jmp into the middle of the function is a dynamic tail
        # call whose target is not a function entry -> fault, never a wrong jump
        r = snippet_exit_status(JT_NOBOUND)
        self.assertEqual(r.returncode, 0x01)
        self.assertIn(b"no translated code", r.stderr)

    def test_table_rewritten_at_run_time_faults(self):
        code, data, c0 = runtime_snippet()
        prog = discover(code, data=data)
        (jt,) = prog.jump_tables.values()
        self.assertEqual(jt.targets, (c0,))
        r = snippet_exit_status(code, data=data)
        self.assertEqual(r.returncode, 0x01)               # translator fault 0xE0000001
        self.assertIn(b"jump-table target outside the analysed table", r.stderr)


if __name__ == "__main__":
    unittest.main()
