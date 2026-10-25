"""Tests for structured, byte-preserving instruction IR."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from recompiler.disasm import disassemble, find_gnu_objdump
from recompiler.ir import build_ir, write_ir
from recompiler.pe import PE

ROOT = os.path.dirname(os.path.dirname(__file__))
EXE = os.path.join(ROOT, "test", "hello.exe")


@unittest.skipUnless(find_gnu_objdump(), "GNU objdump required by the legacy objdump frontend (brew install binutils)")
class InstructionIRTests(unittest.TestCase):
    def test_decoder_preserves_instruction_bytes(self):
        pe = PE(EXE)
        start = pe.image_base + pe.entry_rva
        insns = disassemble(EXE, start, start + 0x50)
        self.assertTrue(insns)
        for insn in insns:
            self.assertEqual(len(insn.encoding), insn.size)
            self.assertTrue(insn.encoding)
            self.assertEqual(len(insn.to_dict()["bytes"]), insn.size * 2)

    def test_ir_contains_cfg_imports_and_relocations(self):
        data = build_ir(EXE)
        self.assertEqual(data["format"], "exe2mac-instruction-ir-v1")
        self.assertEqual(data["instruction_count"], 358)
        self.assertEqual(len(data["instructions"]), 358)
        self.assertEqual(len(data["relocations"]), 8)
        self.assertEqual({x["name"] for x in data["imports"]},
                         {"ExitProcess", "GetStdHandle", "WriteFile"})
        self.assertTrue(any(x["direct_target"] is not None for x in data["instructions"]))
        self.assertTrue(any(x["references"] for x in data["instructions"]))
        self.assertTrue(data["basic_blocks"])

    def test_ir_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "hello-ir.json")
            write_ir(EXE, out)
            with open(out) as f:
                data = json.load(f)
            self.assertEqual(data["image_base"], 0x140000000)

    def test_cli_writes_valid_json(self):
        # Regression: ir_cli previously appended a literal backslash-n,
        # producing a file json.load() rejects.
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "cli-ir.json")
            subprocess.run([sys.executable, "-m", "recompiler.ir_cli", EXE, "-o", out],
                           cwd=ROOT, check=True, capture_output=True)
            with open(out, "rb") as f:
                raw = f.read()
            self.assertTrue(raw.endswith(b"}\n"))
            data = json.loads(raw)
            self.assertEqual(data["instruction_count"], 358)


if __name__ == "__main__":
    unittest.main()
