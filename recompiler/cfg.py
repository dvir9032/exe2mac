"""Recursive-descent control-flow discovery over the Capstone decoder.

Unlike ``analysis.py`` (a linear-sweep approximation kept for backwards
compatibility), this module only decodes bytes that are reachable from known
roots, and it fails closed on any control flow it cannot model.

Roots
-----
* the PE entry point;
* every direct ``call rel32`` target (discovered transitively);
* every DIR64 base-relocation whose *value* points into an executable section.
  Such a value is an absolute code pointer stored in data (e.g. the ``ops[]``
  function-pointer table in ``hello.c``) and is therefore a possible target of
  an indirect call. If such a pointer lands in the middle of an already
  decoded instruction, discovery aborts with ``CFGError``.

Edges
-----
* ``jcc``: taken target and fall-through.
* ``jmp rel``: target only. ``jmp [IAT]`` is an import tail call. Any other
  indirect ``jmp`` (jump tables, computed gotos) raises ``CFGError``.
* ``call rel``: callee becomes a function root; fall-through continues.
* ``call [IAT]``: import call; fall-through continues unless the import is
  known not to return (``ExitProcess``).
* ``call reg`` / ``call [mem]`` (non-IAT): recorded as a *dynamic* call site.
  The translated program resolves the guest target at runtime through a
  dispatcher keyed by guest VA; fall-through continues.
* ``ret`` and traps terminate the block.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .decoder import (FLOW_CALL, FLOW_COND, FLOW_JUMP, FLOW_RET, FLOW_TRAP,
                      Instruction, decode_one)

NORETURN_IMPORTS = frozenset({("kernel32.dll", "ExitProcess")})


class CFGError(RuntimeError):
    pass


@dataclass
class Block:
    start: int
    instructions: list[Instruction]
    successors: list[int]          # intra-procedural successor block starts
    terminator: str                # "fallthrough","jump","cond","ret","call_noreturn","import_tailcall","trap"

    @property
    def end(self) -> int:
        return self.instructions[-1].next


@dataclass
class Function:
    entry: int
    blocks: dict[int, Block] = field(default_factory=dict)


@dataclass(frozen=True)
class CallSite:
    address: int
    kind: str                      # "direct" | "import" | "dynamic"
    target: int | None = None      # callee VA for direct calls
    import_dll: str | None = None
    import_name: str | None = None
    returns: bool = True


@dataclass
class Program:
    image_base: int
    entry: int
    instructions: dict[int, Instruction]
    functions: dict[int, Function]
    call_sites: list[CallSite]
    code_pointer_roots: list[int]

    def mnemonic_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for insn in self.instructions.values():
            out[insn.mnemonic] = out.get(insn.mnemonic, 0) + 1
        return dict(sorted(out.items()))

    def to_dict(self):
        return {
            "image_base": self.image_base,
            "entry": self.entry,
            "instruction_count": len(self.instructions),
            "mnemonics": self.mnemonic_counts(),
            "code_pointer_roots": self.code_pointer_roots,
            "functions": [
                {"entry": f.entry,
                 "blocks": [{"start": b.start, "end": b.end,
                             "instructions": [i.address for i in b.instructions],
                             "successors": b.successors,
                             "terminator": b.terminator}
                            for b in sorted(f.blocks.values(), key=lambda b: b.start)]}
                for f in sorted(self.functions.values(), key=lambda f: f.entry)
            ],
            "call_sites": [cs.__dict__ for cs in self.call_sites],
            "instructions": [self.instructions[a].to_dict() for a in sorted(self.instructions)],
        }


class _Discoverer:
    def __init__(self, pe):
        self.pe = pe
        self.base = pe.image_base
        self.exec_ranges = [(self.base + s.vaddr, self.base + s.vaddr + s.vsize)
                            for s in pe.sections if s.executable]
        self.iat = {self.base + slot: (dll, name) for slot, dll, name in pe.imports}
        self.insns: dict[int, Instruction] = {}
        self.covered: dict[int, int] = {}    # byte VA -> owning instruction VA

    def in_code(self, va, size=1):
        return any(lo <= va and va + size <= hi for lo, hi in self.exec_ranges)

    def decode_at(self, va) -> Instruction:
        if va in self.insns:
            return self.insns[va]
        if va in self.covered:
            raise CFGError(f"0x{va:x} is inside instruction at 0x{self.covered[va]:x} (overlapping decode)")
        if not self.in_code(va):
            raise CFGError(f"control flow reaches 0x{va:x}, outside executable sections")
        rva = va - self.base
        hi = next(h for lo, h in self.exec_ranges if lo <= va < h)
        insn = decode_one(bytes(self.pe.image[rva:rva + min(15, hi - va)]), va)
        for b in range(va, insn.next):
            owner = self.covered.get(b)
            if owner is not None and owner != va:
                raise CFGError(f"instruction at 0x{va:x} overlaps instruction at 0x{owner:x}")
        for b in range(va, insn.next):
            self.covered[b] = va
        self.insns[va] = insn
        return insn

    def iat_operand(self, insn):
        op = insn.operands[0] if insn.operands else None
        if op is not None and op.kind == "mem" and op.mem.rip_target is not None:
            return self.iat.get(op.mem.rip_target)
        return None


def discover(pe) -> Program:
    d = _Discoverer(pe)
    entry = pe.image_base + pe.entry_rva

    pointer_roots = []
    for rva in pe.relocs:
        value = pe.u64(rva)
        if d.in_code(value):
            pointer_roots.append(value)

    func_queue = [entry] + sorted(set(pointer_roots))
    func_roots = set(func_queue)
    call_sites: dict[int, CallSite] = {}
    # per-function: map of instruction -> list of intra-procedural successors
    func_succ: dict[int, dict[int, list[int]]] = {}
    func_term: dict[int, dict[int, str]] = {}

    while func_queue:
        froot = func_queue.pop(0)
        if froot in func_succ:
            continue
        succ: dict[int, list[int]] = {}
        term: dict[int, str] = {}
        work = [froot]
        while work:
            va = work.pop()
            if va in succ:
                continue
            insn = d.decode_at(va)
            nxt: list[int] = []
            kind = "fallthrough"
            if insn.flow == FLOW_COND:
                if insn.direct_target is None:
                    raise CFGError(f"0x{va:x}: indirect conditional branch")
                nxt = [insn.direct_target, insn.next]
                kind = "cond"
            elif insn.flow == FLOW_JUMP:
                if insn.direct_target is not None:
                    nxt = [insn.direct_target]
                    kind = "jump"
                else:
                    imp = d.iat_operand(insn)
                    if imp is None:
                        raise CFGError(f"0x{va:x}: unresolved indirect jump '{insn.text}'")
                    kind = "import_tailcall"
            elif insn.flow == FLOW_CALL:
                if insn.direct_target is not None:
                    call_sites[va] = CallSite(va, "direct", target=insn.direct_target)
                    if insn.direct_target not in func_roots:
                        func_roots.add(insn.direct_target)
                        func_queue.append(insn.direct_target)
                    nxt = [insn.next]
                else:
                    imp = d.iat_operand(insn)
                    if imp is not None:
                        returns = imp not in NORETURN_IMPORTS
                        call_sites[va] = CallSite(va, "import", import_dll=imp[0],
                                                  import_name=imp[1], returns=returns)
                        if returns:
                            nxt = [insn.next]
                        else:
                            kind = "call_noreturn"
                    else:
                        call_sites[va] = CallSite(va, "dynamic")
                        nxt = [insn.next]
            elif insn.flow == FLOW_RET:
                kind = "ret"
            elif insn.flow == FLOW_TRAP:
                kind = "trap"
            else:
                nxt = [insn.next]
            succ[va] = nxt
            term[va] = kind
            for t in nxt:
                work.append(t)
        func_succ[froot] = succ
        func_term[froot] = term

    functions = {}
    for froot, succ in func_succ.items():
        functions[froot] = _build_blocks(froot, succ, func_term[froot], d.insns, func_roots)

    return Program(pe.image_base, entry, dict(sorted(d.insns.items())), functions,
                   sorted(call_sites.values(), key=lambda c: c.address),
                   sorted(set(pointer_roots)))


def _build_blocks(froot, succ, term, insns, func_roots):
    preds: dict[int, int] = {}
    for va, nxt in succ.items():
        for t in nxt:
            preds[t] = preds.get(t, 0) + 1
    leaders = {froot}
    for va, nxt in succ.items():
        k = term[va]
        if k in ("cond", "jump"):
            leaders.update(nxt)
        elif (k != "fallthrough" or insns[va].flow == FLOW_CALL) and insns[va].next in succ:
            # calls end their block so the return point is an explicit block start
            leaders.add(insns[va].next)
    for va, n in preds.items():
        if n > 1:
            leaders.add(va)
    # a function root reached by fall-through from this function also starts a block
    leaders.update(r for r in func_roots if r in succ)

    func = Function(froot)
    for leader in sorted(leaders):
        if leader not in succ:
            continue
        body = []
        va = leader
        while True:
            insn = insns[va]
            body.append(insn)
            k = term[va]
            nxt = succ[va]
            if k != "fallthrough" or len(nxt) != 1 or nxt[0] in leaders or insn.flow == FLOW_CALL:
                break
            va = nxt[0]
        last = body[-1]
        func.blocks[leader] = Block(leader, body, list(succ[last.address]), term[last.address]
                                    if insns[last.address].flow != FLOW_CALL or term[last.address] != "fallthrough"
                                    else "call")
    return func
