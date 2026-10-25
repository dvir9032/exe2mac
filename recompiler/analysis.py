"""Control-flow and address analysis for x86-64 PE images.

This module deliberately analyzes decoded instructions without pretending to
translate their semantics. It is the bridge between disassembly and the later
semantic lifter: branch targets, RIP-relative references, IAT calls and basic
block leaders are made explicit and testable.
"""
from dataclasses import dataclass, asdict
import re
from .disasm import disassemble

_DIRECT_TARGET = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]+)\s*$")
_RIP_DISP = re.compile(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\s*\]", re.I)
_COND_BRANCHES = {"ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge",
                  "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc",
                  "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp",
                  "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz"}
_TERMINATORS = _COND_BRANCHES | {"jmp", "ret", "retq", "ud2", "hlt"}

@dataclass(frozen=True)
class Reference:
    instruction: int
    operand: str
    kind: str
    target_va: int
    target_rva: int | None
    import_dll: str | None = None
    import_name: str | None = None

@dataclass(frozen=True)
class BasicBlock:
    start: int
    end: int
    instruction_count: int
    successors: tuple[int, ...]

@dataclass
class Analysis:
    instruction_count: int
    basic_blocks: list[BasicBlock]
    references: list[Reference]
    unsupported_mnemonics: list[str]

    def to_dict(self):
        return {
            "instruction_count": self.instruction_count,
            "basic_blocks": [asdict(b) for b in self.basic_blocks],
            "references": [asdict(r) for r in self.references],
            "unsupported_mnemonics": self.unsupported_mnemonics,
        }

def _direct_target(insn):
    if not insn.ops:
        return None
    m = _DIRECT_TARGET.match(insn.ops[0])
    if not m:
        return None
    return int(m.group(1), 16)

def _rip_target(insn, operand):
    m = _RIP_DISP.search(operand)
    if not m:
        return None
    disp = int(m.group(2), 0) * (1 if m.group(1) == "+" else -1)
    return insn.next + disp

def analyze(exe_path, pe, start_va=None, end_va=None, supported_mnemonics=None):
    """Analyze one executable range; addresses in results are virtual addresses."""
    if start_va is None:
        start_va = pe.image_base + pe.entry_rva
    if end_va is None:
        text = next((s for s in pe.sections if s.executable and s.vaddr <= pe.entry_rva < s.vaddr + max(s.vsize, s.raw_size)), None)
        if text is None:
            raise ValueError("entry point is not in an executable section")
        end_va = pe.image_base + text.vaddr + max(text.vsize, text.raw_size)
    insns = disassemble(exe_path, start_va, end_va)
    if not insns:
        raise ValueError("no instructions decoded in requested range")

    by_va = {i.addr: i for i in insns}
    next_va = {i.addr: i.next for i in insns}
    leaders = {insns[0].addr}
    branch_targets = {}
    references = []
    iat = {pe.image_base + slot: (dll, name, slot) for slot, dll, name in pe.imports}

    for insn in insns:
        mnem = insn.mnem.lower()
        if mnem in _COND_BRANCHES | {"jmp", "call"}:
            target = _direct_target(insn)
            if target is not None:
                branch_targets[insn.addr] = target
                if target in by_va and mnem != "call":
                    leaders.add(target)
        if mnem in _TERMINATORS and insn.next in by_va:
            leaders.add(insn.next)
        for operand in insn.ops:
            target = _rip_target(insn, operand)
            if target is None:
                continue
            rva = target - pe.image_base
            imp = iat.get(target)
            references.append(Reference(
                instruction=insn.addr, operand=operand,
                kind="iat" if imp else "rip-relative",
                target_va=target,
                target_rva=rva if 0 <= rva < pe.size_of_image else None,
                import_dll=imp[0] if imp else None,
                import_name=imp[1] if imp else None,
            ))

    ordered = sorted(by_va)
    blocks = []
    leader_set = leaders.intersection(by_va)
    starts = sorted(leader_set)
    for idx, block_start in enumerate(starts):
        limit = starts[idx + 1] if idx + 1 < len(starts) else (ordered[-1] + by_va[ordered[-1]].size)
        block_insns = [by_va[a] for a in ordered if block_start <= a < limit]
        if not block_insns:
            continue
        last = block_insns[-1]
        m = last.mnem.lower()
        succ = []
        target = branch_targets.get(last.addr)
        if target is not None and target in by_va:
            succ.append(target)
        if m not in {"jmp", "ret", "retq", "ud2", "hlt"} and last.next in by_va:
            if last.next not in succ:
                succ.append(last.next)
        blocks.append(BasicBlock(block_start, last.next, len(block_insns), tuple(succ)))

    all_mnemonics = {i.mnem.lower() for i in insns}
    unsupported = sorted(all_mnemonics - set(supported_mnemonics or ())) if supported_mnemonics is not None else []
    return Analysis(len(insns), blocks, references, unsupported)
