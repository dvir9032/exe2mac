"""Structured instruction IR export for PE32+ x86-64 fixtures.

This is descriptive IR, not semantic lifting: it preserves decoded bytes,
operands, direct control-flow targets and RIP-relative targets without claiming
the instruction has been translated correctly.
"""
import json
import re
from pathlib import Path

from .analysis import analyze
from .disasm import disassemble
from .pe import PE

_DIRECT = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]+)\b")


def build_ir(exe_path, start=None, end=None):
    pe = PE(exe_path)
    if start is None:
        start = pe.image_base + pe.entry_rva
    if end is None:
        sec = next((s for s in pe.sections
                    if s.executable and s.vaddr <= pe.entry_rva < s.vaddr + max(s.vsize, s.raw_size)), None)
        if sec is None:
            raise ValueError("entry point is not in an executable section")
        end = pe.image_base + sec.vaddr + max(sec.vsize, sec.raw_size)

    insns = disassemble(exe_path, start, end)
    analysis = analyze(exe_path, pe, start, end)
    ref_by_insn = {}
    for ref in analysis.references:
        ref_by_insn.setdefault(ref.instruction, []).append({
            "kind": ref.kind,
            "target_va": ref.target_va,
            "target_rva": ref.target_rva,
            "import_dll": ref.import_dll,
            "import_name": ref.import_name,
            "operand": ref.operand,
        })

    instructions = []
    for insn in insns:
        item = insn.to_dict()
        item["next_address"] = insn.next
        item["direct_target"] = None
        if insn.mnem.lower() in {"call", "jmp"} or insn.mnem.lower().startswith("j"):
            if insn.ops:
                match = _DIRECT.match(insn.ops[0])
                if match:
                    item["direct_target"] = int(match.group(1), 16)
        item["references"] = ref_by_insn.get(insn.addr, [])
        instructions.append(item)

    return {
        "format": "exe2mac-instruction-ir-v1",
        "input": str(exe_path),
        "image_base": pe.image_base,
        "entry_rva": pe.entry_rva,
        "range": {"start": start, "end": end},
        "instruction_count": len(instructions),
        "instructions": instructions,
        "basic_blocks": [
            {"start": b.start, "end": b.end, "instruction_count": b.instruction_count,
             "successors": list(b.successors)}
            for b in analysis.basic_blocks
        ],
        "imports": [
            {"iat_rva": slot, "dll": dll, "name": name}
            for slot, dll, name in pe.imports
        ],
        "relocations": list(pe.relocs),
        "note": "Descriptive decode only; this JSON does not imply semantic translation.",
    }


def write_ir(exe_path, output_path, start=None, end=None):
    data = build_ir(exe_path, start, end)
    Path(output_path).write_text(json.dumps(data, indent=2) + "\n")
    return data
