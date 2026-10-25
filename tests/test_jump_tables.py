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
JT_RUNTIME = ("31c9488d15000000004c8d05f0ffffff4929d044890283f900771889c8488d1500000000"
              "486304824801d0ffe0b801000000c3c3")


def discover(code_hex, data=b""):
    from recompiler.cfg import discover as d
    return d(FakePE(bytes.fromhex(code_hex), data=data))


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
            discover(JT_NOBOUND)

    def test_entry_that_bypasses_the_bounds_check_is_rejected(self):
        from recompiler.cfg import CFGError
        with self.assertRaisesRegex(CFGError, "unresolved indirect jump|from outside its bounds check"):
            discover(JT_BYPASS)

    def test_index_without_zero_extension_is_rejected(self):
        from recompiler.cfg import CFGError
        with self.assertRaisesRegex(CFGError, "unexpected table load"):
            discover(JT_NOZEXT)


@unittest.skipUnless(CC and dec.capstone is not None, "C compiler and capstone required")
class JumpTableExecutionTests(_SnippetCheck, unittest.TestCase):
    def test_in_range_and_default_paths(self):
        self.check(JT_OK, {"rbx": 102, "rsi": 999, "rax": 999, "rcx": 9, "rdx": 0},
                   {"cf": 0, "pf": 1, "af": 0, "zf": 1, "sf": 0, "of": 0})   # from `xor edx, edx`

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
