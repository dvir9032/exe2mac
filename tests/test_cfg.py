"""Tests for recursive-descent CFG discovery."""
import os
import struct
import unittest

from recompiler import decoder as dec
from recompiler.pe import PE

ROOT = os.path.dirname(os.path.dirname(__file__))
EXE = os.path.join(ROOT, "test", "hello.exe")
BASE = 0x140000000


class _Sec:
    def __init__(self, name, vaddr, vsize, executable):
        self.name, self.vaddr, self.vsize, self.raw_size = name, vaddr, vsize, vsize
        self.executable = executable


class FakePE:
    """Minimal in-memory image: code at RVA 0x1000, data at RVA 0x2000."""

    def __init__(self, code, data=b"", imports=(), relocs=()):
        self.image_base = BASE
        self.entry_rva = 0x1000
        self.image = bytearray(0x3000)
        self.image[0x1000:0x1000 + len(code)] = code
        self.image[0x2000:0x2000 + len(data)] = data
        self.sections = [_Sec(".text", 0x1000, len(code), True),
                         _Sec(".rdata", 0x2000, max(len(data), 1), False)]
        self.imports = list(imports)
        self.relocs = list(relocs)

    def u64(self, rva):
        return struct.unpack_from("<Q", self.image, rva)[0]


@unittest.skipUnless(dec.capstone is not None, "capstone is required")
class FixtureCFGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from recompiler.cfg import discover
        cls.prog = discover(PE(EXE))

    def test_functions_found(self):
        self.assertEqual(set(self.prog.functions), {
            0x140001000,                                  # start
            0x140001550,                                  # fib
            0x140001590,                                  # sort
            0x1400015F0, 0x140001600, 0x140001610, 0x140001620,  # op_add/mul/sub/div
        })

    def test_code_pointer_roots_come_from_relocations(self):
        self.assertEqual(self.prog.code_pointer_roots,
                         [0x1400015F0, 0x140001600, 0x140001610, 0x140001620])

    def test_reachable_instruction_count(self):
        self.assertEqual(len(self.prog.instructions), 340)

    def test_reachable_mnemonic_inventory(self):
        self.assertEqual(set(self.prog.mnemonic_counts()), {
            "add", "call", "cdq", "cmovs", "cmp", "dec", "idiv", "imul", "inc",
            "ja", "jae", "jb", "je", "jg", "jle", "jmp", "jne", "jns", "lea",
            "mov", "movabs", "movsxd", "mul", "neg", "nop", "or", "pop", "push",
            "ret", "shr", "sub", "test", "xor"})

    def test_fib_is_self_recursive(self):
        direct = [c for c in self.prog.call_sites if c.kind == "direct"]
        self.assertIn((0x140001563, 0x140001550), {(c.address, c.target) for c in direct})

    def test_import_calls_and_noreturn_exit(self):
        imports = {(c.address, c.import_name, c.returns) for c in self.prog.call_sites if c.kind == "import"}
        self.assertIn((0x140001015, "GetStdHandle", True), imports)
        self.assertIn((0x14000152C, "ExitProcess", False), imports)
        # nothing after the ExitProcess call is decoded as reachable
        self.assertNotIn(0x140001532, self.prog.instructions)
        start = self.prog.functions[0x140001000]
        exit_block = next(b for b in start.blocks.values() if b.end == 0x140001532)
        self.assertEqual(exit_block.terminator, "call_noreturn")
        self.assertEqual(exit_block.successors, [])

    def test_dynamic_call_sites(self):
        dyn = [c.address for c in self.prog.call_sites if c.kind == "dynamic"]
        self.assertEqual(len(dyn), 13)
        self.assertIn(0x1400012D3, dyn)            # call [rsi + rbx*8]  (ops[k])
        self.assertIn(0x14000104A, dyn)            # call r13            (WriteFile via register)

    def test_fib_cfg_edges(self):
        fib = self.prog.functions[0x140001550]
        edges = {b.start: (b.terminator, tuple(b.successors)) for b in fib.blocks.values()}
        self.assertEqual(edges[0x140001550], ("cond", (0x140001574, 0x140001560)))
        self.assertEqual(edges[0x140001574][0], "ret")

    def test_every_block_successor_is_a_block(self):
        for f in self.prog.functions.values():
            for b in f.blocks.values():
                for s in b.successors:
                    self.assertIn(s, f.blocks, f"0x{b.start:x} -> 0x{s:x}")

    def test_deterministic(self):
        from recompiler.cfg import discover
        self.assertEqual(discover(PE(EXE)).to_dict(), self.prog.to_dict())


@unittest.skipUnless(dec.capstone is not None, "capstone is required")
class FailClosedCFGTests(unittest.TestCase):
    def discover(self, *a, strict=False, **k):
        from recompiler.cfg import discover
        return discover(FakePE(*a, **k), strict_indirect_jumps=strict)

    def test_indirect_jump_through_register_is_rejected_in_strict_mode(self):
        from recompiler.cfg import CFGError
        with self.assertRaisesRegex(CFGError, "unresolved indirect jump"):
            self.discover(bytes.fromhex("ffe0"), strict=True)          # jmp rax

    def test_indirect_jump_is_a_dynamic_tail_call_by_default(self):
        prog = self.discover(bytes.fromhex("ffe0"))                     # jmp rax
        self.assertIn(BASE + 0x1000, prog.dynamic_tail_jumps)
        blk = prog.functions[BASE + 0x1000].blocks[BASE + 0x1000]
        self.assertEqual((blk.terminator, blk.successors), ("tailcall_dynamic", []))

    def test_lea_candidate_that_is_not_code_is_dropped(self):
        # lea rax, [rip + 1] ; ret ; 0x0f (truncated opcode at the end of .text)
        prog = self.discover(bytes.fromhex("488d0501000000" "c3" "0f"))
        self.assertIn(BASE + 0x1008, prog.rejected_roots)
        self.assertNotIn(BASE + 0x1008, prog.functions)

    def test_lea_of_a_code_address_creates_a_function_root(self):
        # lea rax, [rip + 2] ; ret ; (target) ret
        prog = self.discover(bytes.fromhex("488d0502000000" "c3" "90" "c3"))
        self.assertIn(BASE + 0x1009, prog.functions)

    def test_branch_outside_code_is_rejected(self):
        from recompiler.cfg import CFGError
        with self.assertRaisesRegex(CFGError, "outside executable"):
            self.discover(bytes.fromhex("e900100000"))    # jmp +0x1000 (into .rdata)

    def test_running_off_end_of_code_is_rejected(self):
        from recompiler.cfg import CFGError
        with self.assertRaises(CFGError):
            self.discover(bytes.fromhex("90"))            # nop, then falls out of .text

    def test_overlapping_instructions_are_rejected(self):
        from recompiler.cfg import CFGError
        # 0x1000: jmp +1 -> 0x1003 would be fine; here jne lands mid-instruction
        code = bytes.fromhex("7501" "b8c3000000" "c3")   # jne 0x1003 (inside mov eax, 0xc3)
        with self.assertRaisesRegex(CFGError, "inside instruction|overlap"):
            self.discover(code)

    def test_undecodable_reachable_bytes_are_rejected(self):
        with self.assertRaises(dec.DecodeError):
            self.discover(bytes.fromhex("0f"))            # truncated opcode

    def test_import_tail_jump_is_accepted(self):
        # jmp [rip + 0xffa] -> 0x140002000 is an IAT slot
        prog = self.discover(bytes.fromhex("ff25fa0f0000"), data=b"\0" * 8,
                             imports=[(0x2000, "kernel32.dll", "ExitProcess")])
        blk = prog.functions[BASE + 0x1000].blocks[BASE + 0x1000]
        self.assertEqual(blk.terminator, "import_tailcall")


@unittest.skipUnless(dec.capstone is not None, "capstone is required")
class CFGCliTests(unittest.TestCase):
    def test_cli_writes_valid_json(self):
        import json, subprocess, sys, tempfile
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "cfg.json")
            subprocess.run([sys.executable, "-m", "recompiler.cfg_cli", EXE, "-o", out],
                           cwd=ROOT, check=True, capture_output=True)
            data = json.load(open(out))
        self.assertEqual(data["format"], "exe2mac-cfg-v1")
        self.assertEqual(data["instruction_count"], 340)
        self.assertEqual(len(data["functions"]), 7)


if __name__ == "__main__":
    unittest.main()
