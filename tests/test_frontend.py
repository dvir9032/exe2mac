"""Regression tests for exe2mac's PE/disassembly front end.
Run from repository root: python3 -m unittest discover -s tests -v
"""
import os
import unittest
from recompiler.pe import PE
from recompiler.disasm import disassemble, find_gnu_objdump, split_operands
from recompiler.analysis import analyze

ROOT = os.path.dirname(os.path.dirname(__file__))
EXE = os.path.join(ROOT, "test", "hello.exe")

class FrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pe = PE(EXE)

    def test_pe_identity(self):
        self.assertEqual(self.pe.entry_rva, 0x1000)
        self.assertEqual(self.pe.image_base, 0x140000000)
        self.assertEqual(self.pe.size_of_image, 0x5000)
        self.assertEqual(self.pe.subsystem, 3)  # Windows console

    def test_imports(self):
        imports = {(dll, name) for _, dll, name in self.pe.imports}
        self.assertTrue({("kernel32.dll", "ExitProcess"),
                         ("kernel32.dll", "GetStdHandle"),
                         ("kernel32.dll", "WriteFile")}.issubset(imports))

    def test_relocations(self):
        self.assertEqual(len(self.pe.relocs), 8)
        self.assertTrue(all(0 <= r < self.pe.size_of_image for r in self.pe.relocs))

    @unittest.skipUnless(find_gnu_objdump(), "GNU objdump required by the legacy objdump frontend (brew install binutils)")
    def test_disassembly_has_control_flow_and_arithmetic(self):
        start = self.pe.image_base + self.pe.entry_rva
        insns = disassemble(EXE, start, start + 0x800)
        self.assertGreater(len(insns), 300)
        mnems = {i.mnem for i in insns}
        self.assertTrue({"call", "ret", "cmp", "jle", "idiv", "mul", "cmovs", "movsxd"}.issubset(mnems))
        self.assertEqual(insns[0].addr, start)

    @unittest.skipUnless(find_gnu_objdump(), "GNU objdump required by the legacy objdump frontend (brew install binutils)")
    def test_control_flow_and_iat_references_are_resolved(self):
        start = self.pe.image_base + self.pe.entry_rva
        result = analyze(EXE, self.pe, start, start + 0x800)
        self.assertEqual(result.instruction_count, 358)
        imported = {(r.import_dll, r.import_name) for r in result.references if r.kind == "iat"}
        self.assertIn(("kernel32.dll", "GetStdHandle"), imported)
        self.assertIn(("kernel32.dll", "WriteFile"), imported)
        self.assertGreater(len(result.basic_blocks), 20)
        self.assertTrue(any(block.successors for block in result.basic_blocks))

    def test_operand_split_respects_memory_brackets(self):
        self.assertEqual(split_operands("rax, QWORD PTR [rsp+rcx*4+0x20], 7"),
                         ["rax", "QWORD PTR [rsp+rcx*4+0x20]", "7"])

if __name__ == "__main__":
    unittest.main()
