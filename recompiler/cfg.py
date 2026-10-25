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
                      DecodeError, Instruction, decode_one)

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


@dataclass(frozen=True)
class JumpTable:
    jmp: int                       # address of the `jmp reg`
    table: int                     # VA of the int32 offset table (entries are relative to it)
    count: int                     # number of entries proven by the bounds check
    targets: tuple[int, ...]       # entry-ordered targets (may repeat)
    bound_check: int               # address of the guarding `cmp`


@dataclass
class Program:
    image_base: int
    entry: int
    instructions: dict[int, Instruction]
    functions: dict[int, Function]
    call_sites: list[CallSite]
    code_pointer_roots: list[int]
    jump_tables: dict[int, JumpTable] = field(default_factory=dict)
    # indirect `jmp`s that are not jump tables: translated as dynamic tail calls
    # (VA -> why the jump-table matcher rejected them)
    dynamic_tail_jumps: dict[int, str] = field(default_factory=dict)
    soft_roots: set[int] = field(default_factory=set)          # accepted `lea` code-pointer roots
    rejected_roots: dict[int, str] = field(default_factory=dict)  # `lea` targets that are not code

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
            "jump_tables": [{"jmp": j.jmp, "table": j.table, "count": j.count,
                             "targets": list(j.targets), "bound_check": j.bound_check}
                            for j in sorted(self.jump_tables.values(), key=lambda j: j.jmp)],
            "dynamic_tail_jumps": [{"jmp": va, "reason": r} for va, r in sorted(self.dynamic_tail_jumps.items())],
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


def discover(pe, strict_indirect_jumps: bool = False) -> Program:
    """Discover reachable code.

    An indirect ``jmp`` that is neither an IAT tail call nor a recognised jump
    table is treated as a *dynamic tail call*: the translated code jumps to the
    run-time target through the function dispatcher, which faults unless the
    target is a known function entry or import. With
    ``strict_indirect_jumps=True`` such jumps are rejected at translation time
    instead (the pre-tail-call behaviour).
    """
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
    jump_tables: dict[int, JumpTable] = {}
    dynamic_tail_jumps: dict[int, str] = {}
    # `lea reg, [rip + code]` targets: candidate function roots, explored last
    lea_targets: set[int] = set()
    # per-function: map of instruction -> list of intra-procedural successors
    func_succ: dict[int, dict[int, list[int]]] = {}
    func_term: dict[int, dict[int, str]] = {}

    def add_root(va):
        if va not in func_roots:
            func_roots.add(va)
            func_queue.append(va)

    def explore(froot):
        succ: dict[int, list[int]] = {}
        term: dict[int, str] = {}
        preds: dict[int, set[int]] = {}
        func_tables: list[tuple[JumpTable, list[int]]] = []
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
                    if imp is not None:
                        kind = "import_tailcall"
                    else:
                        try:
                            jt, chain = _match_jump_table(d, insn, preds)
                        except CFGError as exc:
                            if strict_indirect_jumps:
                                raise
                            dynamic_tail_jumps[va] = str(exc).split(" (", 1)[-1].rstrip(")")
                            kind = "tailcall_dynamic"
                        else:
                            jump_tables[va] = jt
                            func_tables.append((jt, chain))
                            nxt = sorted(set(jt.targets))
                            kind = "jump_table"
            elif insn.flow == FLOW_CALL:
                if insn.direct_target is not None:
                    call_sites[va] = CallSite(va, "direct", target=insn.direct_target)
                    add_root(insn.direct_target)
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
                if (insn.mnemonic == "lea" and len(insn.operands) == 2 and insn.operands[1].kind == "mem"
                        and insn.operands[1].mem.rip_target is not None
                        and d.in_code(insn.operands[1].mem.rip_target)):
                    lea_targets.add(insn.operands[1].mem.rip_target)
                nxt = [insn.next]
            succ[va] = nxt
            term[va] = kind
            for t in nxt:
                preds.setdefault(t, set()).add(va)
                work.append(t)
        # The bounds proof assumed the guard -> jmp chain is entered only through
        # the guard. Re-check now that every edge of the function is known.
        for jt, chain in func_tables:
            for prev, cur in zip(chain, chain[1:]):
                if preds.get(cur, set()) != {prev}:
                    raise CFGError(f"0x{jt.jmp:x}: jump-table sequence is entered at 0x{cur:x} "
                                   "from outside its bounds check")
        func_succ[froot] = succ
        func_term[froot] = term

    def drain():
        while func_queue:
            froot = func_queue.pop(0)
            if froot not in func_succ:
                explore(froot)

    drain()   # certain roots: any failure is a translation error

    # Candidate roots from `lea [rip + code]` (function pointers). They might be
    # data inside .text (e.g. an MSVC jump table) or a mid-function label, so
    # each is explored in a transaction and dropped if it does not decode into
    # valid control flow. A dropped candidate is not callable: an indirect call
    # to it faults at run time instead of executing undecoded bytes.
    table_bases = {j.table for j in jump_tables.values()}
    soft_roots: set[int] = set()
    rejected_roots: dict[int, str] = {}
    done: set[int] = set()
    while True:
        pending = sorted(lea_targets - done - table_bases - set(func_succ))
        if not pending:
            break
        cand = pending[0]
        done.add(cand)
        if cand in d.covered and d.covered[cand] != cand:
            rejected_roots[cand] = "inside another instruction"
            continue
        snapshot = (dict(d.insns), dict(d.covered), dict(func_succ), dict(func_term), dict(call_sites),
                    dict(jump_tables), dict(dynamic_tail_jumps), set(func_roots), set(lea_targets))
        func_roots.add(cand)
        func_queue[:] = [cand]
        try:
            drain()
        except (CFGError, DecodeError) as exc:
            (d.insns, d.covered, func_succ, func_term, call_sites, jump_tables,
             dynamic_tail_jumps, func_roots, lea_targets) = snapshot
            func_queue[:] = []
            rejected_roots[cand] = str(exc)
            continue
        soft_roots.add(cand)
        table_bases = {j.table for j in jump_tables.values()}

    functions = {}
    for froot, succ in func_succ.items():
        functions[froot] = _build_blocks(froot, succ, func_term[froot], d.insns, func_roots)

    return Program(pe.image_base, entry, dict(sorted(d.insns.items())), functions,
                   sorted(call_sites.values(), key=lambda c: c.address),
                   sorted(set(pointer_roots)), jump_tables, dynamic_tail_jumps, soft_roots, rejected_roots)


MAX_JUMP_TABLE_ENTRIES = 4096

# Windows x64 callee-saved GPRs (hardware indices): RBX RBP RSI RDI R12-R15.
_NONVOLATILE = frozenset({3, 5, 6, 7, 12, 13, 14, 15})


def _upper_half_zero(d, preds, va, reg_index, limit=64):
    """Prove that bits 32..63 of GPR `reg_index` are zero on entry to `va`:
    walk back along a unique-predecessor chain to the last instruction that
    writes the register; a 32-bit write zero-extends. Calls are crossed only
    for callee-saved registers. Anything else -> False (no proof)."""
    from .decoder import make_register
    cur = va
    for _ in range(limit):
        ps = preds.get(cur, set())
        if len(ps) != 1:
            return False
        (cur,) = ps
        insn = d.insns[cur]
        if insn.flow == FLOW_CALL:
            if reg_index in _NONVOLATILE:
                continue
            return False
        widths = [make_register(n).width for n in insn.regs_written
                  if make_register(n).kind == "gpr" and make_register(n).index == reg_index]
        if widths:
            return widths == [32] and not any(make_register(n).high8 for n in insn.regs_written
                                              if make_register(n).kind == "gpr")
    return False


def _match_jump_table(d, jmp, preds):
    """Recognise the bounded relative jump-table idiom ending at ``jmp``:

        cmp  IDX, N        ; IDX is a 32- or 64-bit GPR
        ja   default       ; (or jae -> N entries instead of N+1)
        [mov r32, IDX32]   ; optional zero-extending copy of the index
        lea  B, [rip+T]
        movsxd R, dword ptr [B + I*4]
        add  R, B          ; (or add B, R and jmp B)
        jmp  R

    The instructions are evaluated symbolically; any instruction in the chain
    that is not one of these exact forms makes the match fail (CFGError).
    Returns (JumpTable, chain-of-addresses-from-the-ja-to-the-jmp).
    """
    def fail(why):
        return CFGError(f"0x{jmp.address:x}: unresolved indirect jump '{jmp.text}' ({why})")

    op = jmp.operands[0] if jmp.operands else None
    if op is None or op.kind != "reg" or op.reg.kind != "gpr" or op.reg.width != 64:
        raise fail("not a jump through a 64-bit register")

    chain = [jmp.address]
    cur = jmp.address
    guard = None
    for _ in range(12):
        ps = preds.get(cur, set())
        if len(ps) != 1:
            raise fail("no unique fall-through predecessor")
        (p,) = ps
        pin = d.insns[p]
        if pin.next != cur:
            raise fail("predecessor is a branch, not fall-through")
        chain.insert(0, p)
        if pin.mnemonic in ("ja", "jae"):
            guard = pin
            break
        cur = p
    if guard is None:
        raise fail("no bounds check found")
    gp = preds.get(guard.address, set())
    if len(gp) != 1:
        raise fail("bounds check has no unique predecessor")
    (cmp_va,) = gp
    cmp = d.insns[cmp_va]
    if cmp.mnemonic != "cmp" or cmp.next != guard.address or len(cmp.operands) != 2:
        raise fail("bounds check is not `cmp reg, imm` immediately before the branch")
    idx_op, lim_op = cmp.operands
    if idx_op.kind != "reg" or idx_op.reg.kind != "gpr" or idx_op.reg.width not in (32, 64)             or idx_op.reg.high8 or lim_op.kind != "imm":
        raise fail("bounds check is not `cmp r32/r64, imm`")
    limit = lim_op.imm
    count = limit + 1 if guard.mnemonic == "ja" else limit
    if not 0 < count <= MAX_JUMP_TABLE_ENTRIES:
        raise fail(f"implausible table size {count}")

    # symbolic register state: full-register index -> ("idx",) | ("base", T) | ("entry", T) | ("target", T)
    sym = {}
    if idx_op.reg.width == 64:
        sym[idx_op.reg.index] = ("idx",)
    idx32 = idx_op.reg.index if idx_op.reg.width == 32 else None   # zero-extension still required
    if idx32 is not None and _upper_half_zero(d, preds, cmp.address, idx32):
        sym[idx32] = ("idx",)          # the full 64-bit register already equals the bounded index

    def regs(insn):
        return [o for o in insn.operands]

    for va in chain[1:-1]:
        insn = d.insns[va]
        ops = regs(insn)
        mn = insn.mnemonic
        if mn == "mov" and len(ops) == 2 and all(o.kind == "reg" and o.reg.kind == "gpr" for o in ops)                 and ops[0].reg.width == ops[1].reg.width and ops[0].reg.width in (32, 64):
            dst, src = ops
            src_sym = sym.get(src.reg.index)
            if dst.reg.width == 32 and idx32 is not None and src.reg.index == idx32:
                sym[dst.reg.index] = ("idx",)          # 32-bit mov zero-extends the bounded index
            elif dst.reg.width == 64 and src_sym is not None:
                sym[dst.reg.index] = src_sym
            else:
                raise fail(f"unexpected copy at 0x{va:x}")
            if dst.reg.index == idx32:
                idx32 = None
        elif mn == "lea" and len(ops) == 2 and ops[0].kind == "reg" and ops[0].reg.width == 64                 and ops[1].kind == "mem" and ops[1].mem.rip_target is not None:
            sym[ops[0].reg.index] = ("base", ops[1].mem.rip_target)
            if ops[0].reg.index == idx32:
                idx32 = None
        elif mn == "movsxd" and len(ops) == 2 and ops[0].kind == "reg" and ops[0].reg.width == 64                 and ops[1].kind == "mem" and ops[1].size == 4:
            m = ops[1].mem
            b = sym.get(m.base.index) if m.base is not None and m.base.kind == "gpr" else None
            i = sym.get(m.index.index) if m.index is not None and m.index.kind == "gpr" else None
            if not (b and b[0] == "base" and i == ("idx",) and m.scale == 4 and m.disp == 0
                    and m.segment is None and m.index.width == 64):
                raise fail(f"unexpected table load at 0x{va:x}")
            sym[ops[0].reg.index] = ("entry", b[1])
            if ops[0].reg.index == idx32:
                idx32 = None
        elif mn == "add" and len(ops) == 2 and all(o.kind == "reg" and o.reg.width == 64 for o in ops):
            a, b = sym.get(ops[0].reg.index), sym.get(ops[1].reg.index)
            pair = {a[0] if a else None, b[0] if b else None}
            if pair != {"entry", "base"} or a[1] != b[1]:
                raise fail(f"unexpected add at 0x{va:x}")
            sym[ops[0].reg.index] = ("target", a[1])
        elif mn in ("ja", "jae") and va == chain[0]:
            continue
        else:
            raise fail(f"unexpected instruction '{insn.text}' at 0x{va:x}")

    final = sym.get(op.reg.index)
    if not final or final[0] != "target":
        raise fail("jump register is not table base + table entry")
    table = final[1]
    targets = []
    for k in range(count):
        ea = table + 4 * k
        rva = ea - d.base
        if not (0 <= rva and rva + 4 <= len(d.pe.image)):
            raise fail(f"table entry {k} outside the image")
        raw = int.from_bytes(bytes(d.pe.image[rva:rva + 4]), "little", signed=True)
        t = (table + raw) & ((1 << 64) - 1)
        if not d.in_code(t):
            raise fail(f"table entry {k} -> 0x{t:x} is not in an executable section")
        targets.append(t)
    return JumpTable(jmp.address, table, count, tuple(targets), cmp.address), [cmp.address] + chain


def _build_blocks(froot, succ, term, insns, func_roots):
    preds: dict[int, int] = {}
    for va, nxt in succ.items():
        for t in nxt:
            preds[t] = preds.get(t, 0) + 1
    leaders = {froot}
    for va, nxt in succ.items():
        k = term[va]
        if k in ("cond", "jump", "jump_table"):
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
