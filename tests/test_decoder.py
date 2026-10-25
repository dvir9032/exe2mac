"""Unit tests for the Capstone-based structured decoder."""
import os
import unittest

from recompiler import decoder as dec
from recompiler.disasm import find_gnu_objdump

ROOT = os.path.dirname(os.path.dirname(__file__))
EXE = os.path.join(ROOT, "test", "hello.exe")

HAVE_CS = dec.capstone is not None


def one(hexbytes, addr=0x140001000):
    return dec.decode_one(bytes.fromhex(hexbytes), addr)


class RegisterModelTests(unittest.TestCase):
    def test_gpr_aliases_map_to_hardware_index_and_width(self):
        cases = {"rax": (0, 64, False), "eax": (0, 32, False), "ax": (0, 16, False),
                 "al": (0, 8, False), "ah": (0, 8, True), "spl": (4, 8, False),
                 "r8d": (8, 32, False), "r11b": (11, 8, False), "r15w": (15, 16, False),
                 "rdi": (7, 64, False), "bh": (3, 8, True)}
        for name, (idx, width, high) in cases.items():
            r = dec.make_register(name)
            self.assertEqual((r.kind, r.index, r.width, r.high8), ("gpr", idx, width, high), name)

    def test_full_register_name(self):
        self.assertEqual(dec.make_register("r9d").full, "r9")
        self.assertEqual(dec.make_register("ch").full, "rcx")

    def test_non_gpr_registers_are_marked_other(self):
        self.assertEqual(dec.make_register("xmm0").kind, "other")
        self.assertEqual(dec.make_register("rip").kind, "rip")
        self.assertIsNone(dec.make_register("xmm0").full)


@unittest.skipUnless(HAVE_CS, "capstone is required")
class OperandDecodeTests(unittest.TestCase):
    def test_sign_extended_imm8_is_masked_to_operand_size(self):
        i = one("4883c6fe")                     # add rsi, -2
        self.assertEqual(i.mnemonic, "add")
        self.assertEqual(i.operands[0].reg.name, "rsi")
        self.assertEqual(i.operands[1].size, 8)
        self.assertEqual(i.operands[1].imm, 0xFFFFFFFFFFFFFFFE)
        self.assertEqual(i.operands[1].imm_signed, -2)

    def test_imm32_on_32bit_destination(self):
        i = one("41b8ffffffff")                 # mov r8d, 0xffffffff
        self.assertEqual(i.operands[0].reg.index, 8)
        self.assertEqual(i.operands[0].reg.width, 32)
        self.assertEqual(i.operands[1].imm, 0xFFFFFFFF)
        self.assertEqual(i.operands[1].imm_signed, -1)

    def test_movabs_imm64(self):
        i = one("48bdcdcccccccccccccc")         # movabs rbp, 0xcccccccccccccccd
        self.assertEqual(i.operands[1].imm, 0xCCCCCCCCCCCCCCCD)
        self.assertEqual(i.operands[0].reg.full, "rbp")

    def test_sib_memory_operand(self):
        i = one("46885c0c30")                   # mov byte ptr [rsp + r9 + 0x30], r11b
        m = i.operands[0].mem
        self.assertEqual((m.base.name, m.index.name, m.scale, m.disp), ("rsp", "r9", 1, 0x30))
        self.assertEqual(i.operands[0].size, 1)
        self.assertEqual(i.operands[1].reg.name, "r11b")
        self.assertIsNone(m.rip_target)

    def test_negative_displacement(self):
        i = one("468b4c81fc")                   # mov r9d, dword ptr [rcx + r8*4 - 4]
        m = i.operands[1].mem
        self.assertEqual((m.base.name, m.index.name, m.scale, m.disp), ("rcx", "r8", 4, -4))
        self.assertEqual(i.operands[1].size, 4)

    def test_rip_relative_target_uses_next_instruction_address(self):
        i = one("488b0dac1f0000", 0x14000104D)  # mov rcx, qword ptr [rip + 0x1fac]
        self.assertEqual(i.operands[1].mem.rip_target, 0x14000104D + 7 + 0x1FAC)
        self.assertEqual(i.operands[1].mem.rip_target, 0x140003000)

    def test_lea_32bit_destination(self):
        i = one("8d0412")                       # lea eax, [rdx + rdx]
        self.assertEqual(i.mnemonic, "lea")
        self.assertEqual(i.operands[0].reg.width, 32)
        self.assertEqual((i.operands[1].mem.base.name, i.operands[1].mem.index.name), ("rdx", "rdx"))

    def test_store_imm16(self):
        i = one("66c744244d2d34")               # mov word ptr [rsp + 0x4d], 0x342d
        self.assertEqual(i.operands[0].size, 2)
        self.assertEqual(i.operands[1].imm, 0x342D)


@unittest.skipUnless(HAVE_CS, "capstone is required")
class ControlFlowDecodeTests(unittest.TestCase):
    def test_conditional_branch_target_and_tested_flags(self):
        i = one("7e14", 0x14000155E)            # jle +0x14
        self.assertEqual(i.flow, dec.FLOW_COND)
        self.assertEqual(i.direct_target, 0x140001574)
        self.assertEqual(set(i.flags_tested), {"ZF", "SF", "OF"})

    def test_backward_rel32_branch(self):
        i = one("0f8221ffffff", 0x140001169)    # jb -0xdf
        self.assertEqual(i.direct_target, 0x140001090)
        self.assertEqual(i.flags_tested, ("CF",))

    def test_direct_call(self):
        i = one("e8b9040000", 0x140001092)
        self.assertEqual((i.flow, i.direct_target, i.is_indirect), (dec.FLOW_CALL, 0x140001550, False))

    def test_indirect_calls(self):
        iat = one("ff15dd100000", 0x140001015)
        self.assertTrue(iat.is_indirect)
        self.assertEqual(iat.operands[0].mem.rip_target, 0x1400020F8)
        reg = one("41ffd5")
        self.assertTrue(reg.is_indirect)
        self.assertEqual(reg.operands[0].reg.name, "r13")
        table = one("ff14de")
        self.assertEqual((table.operands[0].mem.base.name, table.operands[0].mem.index.name,
                          table.operands[0].mem.scale), ("rsi", "rbx", 8))

    def test_ret_and_trap(self):
        self.assertEqual(one("c3").flow, dec.FLOW_RET)
        self.assertEqual(one("0f0b").flow, dec.FLOW_TRAP)   # ud2
        self.assertEqual(one("cc").flow, dec.FLOW_TRAP)     # int3

    def test_flag_effects_metadata(self):
        self.assertEqual(set(one("4883c6fe").flags_modified), {"CF", "PF", "AF", "ZF", "SF", "OF"})
        mul = one("48f7e5")
        self.assertEqual(set(mul.flags_modified), {"CF", "OF"})
        self.assertEqual(set(mul.flags_undefined), {"PF", "AF", "ZF", "SF"})
        self.assertEqual(one("480f48c0").flags_tested, ("SF",))      # cmovs
        self.assertEqual(one("8d0412").flags_modified, ())           # lea

    def test_undecodable_or_truncated_bytes_fail_closed(self):
        with self.assertRaises(dec.DecodeError):
            one("8834")                         # truncated: missing SIB byte
        with self.assertRaises(dec.DecodeError):
            one("")

    def test_linear_decode_is_contiguous(self):
        insns = dec.decode_linear(bytes.fromhex("5657" "4883ec28" "c3"), 0x1000)
        self.assertEqual([i.address for i in insns], [0x1000, 0x1001, 0x1002, 0x1006])
        self.assertEqual([i.mnemonic for i in insns], ["push", "push", "sub", "ret"])


@unittest.skipUnless(HAVE_CS, "capstone is required")
@unittest.skipUnless(find_gnu_objdump(), "GNU objdump required by the legacy objdump frontend (brew install binutils)")
class CrossCheckWithObjdumpTests(unittest.TestCase):
    """Capstone and objdump must agree on boundaries and bytes for the fixture."""

    def test_reachable_instructions_match_objdump_boundaries_and_bytes(self):
        from recompiler.cfg import discover
        from recompiler.disasm import disassemble
        from recompiler.pe import PE
        pe = PE(EXE)
        prog = discover(pe)
        text = next(s for s in pe.sections if s.name == ".text")
        lo = pe.image_base + text.vaddr
        objd = {i.addr: i for i in disassemble(EXE, lo, lo + text.vsize)}
        for va, insn in prog.instructions.items():
            self.assertIn(va, objd, f"0x{va:x} not an objdump boundary")
            self.assertEqual(insn.size, objd[va].size, f"size mismatch at 0x{va:x}")
            self.assertEqual(insn.encoding, objd[va].encoding, f"bytes mismatch at 0x{va:x}")


if __name__ == "__main__":
    unittest.main()
