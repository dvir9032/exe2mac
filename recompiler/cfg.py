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

from .decoder import (FLOW_CALL, FLOW_COND, FLOW_JUMP, FLOW_NONE, FLOW_RET, FLOW_TRAP,
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

    # Relocated pointers into executable sections are candidate roots, like
    # `lea [rip + code]`: compilers also place data (strings, tables) in .text,
    # so they are explored transactionally below, not trusted.
    func_queue = [entry]
    func_roots = set(func_queue)
    call_sites: dict[int, CallSite] = {}
    jump_tables: dict[int, JumpTable] = {}
    dynamic_tail_jumps: dict[int, str] = {}
    # `lea reg, [rip + code]` targets: candidate function roots, explored last
    lea_targets: set[int] = set(pointer_roots)
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
        func_tables: list[tuple[JumpTable, list]] = []   # (table, [(va, required preds)])
        pending: dict[int, tuple[PendingTable, list[int]]] = {}
        resolved: dict[int, tuple[PendingTable, int]] = {}
        work = [froot]
        while True:
            if not work:
                # Tables whose base register was set before the bounds check:
                # resolve with reaching definitions over the edges known so far;
                # new targets may add edges, so iterate (and re-verify at the end).
                for jva, (pt, chain) in list(pending.items()):
                    table = _reaching_lea(d, preds, pt.load, pt.base_reg)
                    if table is None:
                        continue
                    jt = _table_targets(d, d.insns[jva], _with_base(pt.desc, table), pt.count, pt.bound_check)
                    del pending[jva]
                    resolved[jva] = (pt, table)
                    jump_tables[jva] = jt
                    func_tables.append((jt, chain))
                    succ[jva] = sorted(set(jt.targets))
                    term[jva] = "jump_table"
                    for t in succ[jva]:
                        preds.setdefault(t, set()).add(jva)
                        work.append(t)
                if not work:
                    break
                continue
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
                            if isinstance(jt, PendingTable):
                                pending[va] = (jt, chain)      # resolved once the function is explored
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
        for jva, (pt, chain) in pending.items():          # never resolved: dynamic tail call
            if strict_indirect_jumps:
                raise CFGError(f"0x{jva:x}: unresolved indirect jump (table base register not a unique "
                               "`lea [rip+T]` on every path)")
            dynamic_tail_jumps[jva] = "table base register not a unique `lea [rip+T]` on every path"
        for jva, (pt, table) in resolved.items():          # the base must still be unique on the full graph
            if _reaching_lea(d, preds, pt.load, pt.base_reg) != table:
                raise CFGError(f"0x{jva:x}: jump-table base changed after its targets were explored")
        # The bounds proof assumed the guard -> jmp chain is entered only through
        # the guard. Re-check now that every edge of the function is known.
        for jt, proof in func_tables:
            if any(preds.get(va, set()) != set(expect) for va, expect in proof):
                # edges found later (e.g. a second guard re-entering the sequence):
                # the table is accepted only if it re-matches on the complete graph
                try:
                    again, proof = _match_jump_table(d, d.insns[jt.jmp], preds)
                except CFGError:
                    again = None
                if isinstance(again, PendingTable):
                    t = _reaching_lea(d, preds, again.load, again.base_reg)
                    again = None if t is None else _table_targets(d, d.insns[jt.jmp], _with_base(again.desc, t),
                                                                  again.count, again.bound_check)
                if again is None or (again.table, again.count) != (jt.table, jt.count):
                    proof = [(jt.jmp, None)]
            for va, expect in proof:
                if expect is None or preds.get(va, set()) != set(expect):
                    raise CFGError(f"0x{jt.jmp:x}: jump-table sequence is entered at 0x{va:x} "
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
                   sorted(r for r in set(pointer_roots) if r in functions), jump_tables, dynamic_tail_jumps,
                   soft_roots, rejected_roots)


MAX_JUMP_TABLE_ENTRIES = 4096

# Windows x64 callee-saved GPRs (hardware indices): RBX RBP RSI RDI R12-R15.
_NONVOLATILE = frozenset({3, 5, 6, 7, 12, 13, 14, 15})


def _upper_half_zero(d, preds, va, reg_index, limit=4096, sext_ok=False):
    """Prove that bits 32..63 of GPR `reg_index` are zero on entry to `va`:
    on every intra-procedural path backwards, the last instruction writing the
    register must be a plain 32-bit write (which zero-extends). Calls are
    crossed only for callee-saved registers; reaching the function entry, an
    unknown predecessor set, or any other write gives False (no proof).
    The result depends on the edges known so far; jump tables re-verify their
    proof on the complete graph."""
    from .decoder import make_register
    seen, stack = set(), [va]
    while stack:
        cur = stack.pop()
        ps = preds.get(cur, set())
        if not ps:
            return False
        for p in ps:
            if p in seen:
                continue
            seen.add(p)
            if len(seen) > limit:
                return False
            insn = d.insns[p]
            w = [make_register(n) for n in insn.regs_written
                 if make_register(n).kind == "gpr" and make_register(n).index == reg_index]
            if not w:
                if insn.flow == FLOW_CALL and reg_index not in _NONVOLATILE:
                    return False
                stack.append(p)
                continue
            if sext_ok and _sign_extends_32(insn, reg_index):
                continue          # sign-extension of a value later proven < 2^31 leaves bits 32..63 zero
            if not (all(r.width == 32 for r in w) and not any(make_register(n).high8 for n in insn.regs_written
                                                             if make_register(n).kind == "gpr")):
                return False
    return True


@dataclass(frozen=True)
class PendingTable:
    """A bounded table whose base register is set before the bounds check."""
    jmp: int
    base_reg: int                  # GPR index holding the table base
    load: int                      # VA of the `movsxd` that reads the table
    count: int
    bound_check: int
    desc: tuple = ()               # target descriptor with the base still symbolic


def _with_base(desc, table_base):
    return (desc[0], table_base) + tuple(desc[2:])


def _writes_gpr(insn, index):
    from .decoder import make_register
    return [make_register(n) for n in insn.regs_written
            if make_register(n).kind == "gpr" and make_register(n).index == index]


def _sign_extends_32(insn, reg_index):
    """`movsxd r64, r/m32` or `cdqe` writing GPR `reg_index` from a 32-bit value."""
    ops = insn.operands
    if insn.mnemonic == "cdqe":
        return reg_index == 0
    return (insn.mnemonic == "movsxd" and len(ops) == 2 and ops[0].kind == "reg" and ops[0].reg.width == 64
            and ops[0].reg.index == reg_index and ops[1].size == 4)


def _copy_before(d, preds, va, reg_index, limit=8):
    """`mov X32, R32` shortly before `va` (unique-predecessor walk) with neither
    register written in between: X then holds R zero-extended. Returns X."""
    cur, clobbered = va, set()
    for _ in range(limit):
        ps = preds.get(cur, set())
        if len(ps) != 1:
            return None
        (cur,) = ps
        insn = d.insns[cur]
        if insn.flow != FLOW_NONE:
            return None
        ops = insn.operands
        if insn.mnemonic == "mov" and len(ops) == 2 and all(o.kind == "reg" and o.reg.kind == "gpr" for o in ops) \
                and ops[0].reg.width == 32 and ops[1].reg.width == 32 and ops[1].reg.index == reg_index \
                and ops[0].reg.index not in clobbered and ops[0].reg.index != reg_index:
            return ops[0].reg.index
        if _writes_gpr(insn, reg_index):
            return None
        from .decoder import make_register
        clobbered.update(make_register(n).index for n in insn.regs_written if make_register(n).kind == "gpr")
    return None


def _reaching_lea(d, preds, va, reg_index):
    """All definitions of GPR `reg_index` reaching instruction `va`, searched
    backwards over every intra-procedural path. Returns the table VA T if every
    reaching definition is `lea reg64, [rip + T]` with the same T; None otherwise.
    Calls are crossed only for callee-saved registers; reaching the function
    entry without a definition gives None."""
    seen, defs, stack = set(), set(), [va]
    while stack:
        cur = stack.pop()
        ps = preds.get(cur, set())
        if not ps:
            return None                                # function entry: value comes from the caller
        for p in ps:
            if p in seen:
                continue
            seen.add(p)
            insn = d.insns[p]
            w = _writes_gpr(insn, reg_index)
            if insn.flow == FLOW_CALL and not w:
                if reg_index not in _NONVOLATILE:
                    return None
                stack.append(p)
                continue
            if not w:
                stack.append(p)
                continue
            ops = insn.operands
            if insn.mnemonic == "lea" and len(ops) == 2 and len(w) == 1 and w[0].width == 64 \
                    and ops[1].kind == "mem" and ops[1].mem.rip_target is not None:
                defs.add(ops[1].mem.rip_target)
                if len(defs) > 1:
                    return None
            else:
                return None
    return defs.pop() if len(defs) == 1 else None


def _same_mem(a, b):
    return (a.base, a.index, a.scale, a.disp, a.segment) == (b.base, b.index, b.scale, b.disp, b.segment)


def _match_mem_index(d, body, mem, fail):
    """Bounds check on a memory operand: the first instruction of the guarded
    sequence must re-load exactly that dword into a 32-bit register
    (zero-extending). The guard edge leads straight to it, so nothing runs in
    between. Returns the register index."""
    first = d.insns[body[0]]
    if first.mnemonic != "mov" or len(first.operands) != 2:
        raise fail("memory bounds check not followed by a re-load")
    dst, src = first.operands
    if not (dst.kind == "reg" and dst.reg.kind == "gpr" and dst.reg.width == 32 and src.kind == "mem"
            and src.size == 4 and _same_mem(src.mem, mem)):
        raise fail("memory bounds check not followed by a re-load of the same dword")
    return dst.reg.index


def _operand_key(op):
    if op.kind == "reg":
        return ("reg", op.reg.index, op.reg.width, op.reg.high8)
    m = op.mem
    return ("mem", op.size, m.base, m.index, m.scale, m.disp, m.segment, m.rip_target)


def _guard_edges(d, preds, ps, cur):
    """If every predecessor edge into `cur` is a bounds-check edge
    (`cmp X, N` directly followed by a branch that reaches `cur` only when
    X <= N, unsigned: ja/jae fall-through or jbe/jb taken), return
    [(branch, cmp, entry_count)], else None."""
    if not ps:
        return None
    out = []
    for p in ps:
        br = d.insns[p]
        if br.mnemonic in ("ja", "jae") and br.next == cur and br.direct_target != cur:
            inclusive = br.mnemonic == "ja"
        elif br.mnemonic in ("jbe", "jb") and br.direct_target == cur and br.next != cur:
            inclusive = br.mnemonic == "jbe"
        else:
            return None
        cps = preds.get(p, set())
        if len(cps) != 1:
            return None
        (c,) = cps
        cmp = d.insns[c]
        if cmp.mnemonic != "cmp" or cmp.next != p or len(cmp.operands) != 2 or cmp.operands[1].kind != "imm":
            return None
        x = cmp.operands[0]
        if x.kind == "reg":
            if x.reg.kind != "gpr" or x.reg.width not in (8, 16, 32, 64) or x.reg.high8:
                return None
        elif not (x.kind == "mem" and x.size == 4 and x.mem.segment is None and x.mem.rip_target is None):
            return None
        n = cmp.operands[1].imm & ((1 << (x.size * 8 if x.kind == "mem" else x.reg.width)) - 1)
        out.append((p, cmp, n + 1 if inclusive else n))
    return out


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

    body = [jmp.address]                  # chain head .. jmp, entered only through the guard edges
    cur = jmp.address
    guards = None
    for _ in range(12):
        ps = preds.get(cur, set())
        guards = _guard_edges(d, preds, ps, cur)
        if guards:
            break
        if len(ps) != 1:
            raise fail("no unique fall-through predecessor")
        (p,) = ps
        pin = d.insns[p]
        if pin.next != cur:
            raise fail("predecessor is a branch, not fall-through")
        if pin.flow != FLOW_NONE:
            raise fail(f"control flow inside the table sequence at 0x{p:x}")
        body.insert(0, p)
        cur = p
    if not guards:
        raise fail("no bounds check found")
    counts = {g[2] for g in guards}
    xs = {_operand_key(g[1].operands[0]) for g in guards}
    if len(counts) != 1 or len(xs) != 1:
        raise fail("bounds checks on different operands or limits")
    count = counts.pop()
    if not 0 < count <= MAX_JUMP_TABLE_ENTRIES:
        raise fail(f"implausible table size {count}")
    if len(body) < 2:
        raise fail("no table load after the bounds check")
    cmps = [g[1] for g in guards]
    cmp = min(cmps, key=lambda c: c.address)
    idx_op = cmp.operands[0]
    mem_idx = idx_op.mem if idx_op.kind == "mem" else None
    # every edge into the sequence must still be exactly these after exploration
    proof = [(body[0], frozenset(g[0] for g in guards))]
    proof += [(g[0], frozenset({g[1].address})) for g in guards]
    proof += [(b, frozenset({a})) for a, b in zip(body, body[1:])]

    # symbolic register state: full-register index -> ("idx",) | ("base", T) | ("entry", T) | ("target", T)
    sym = {}
    reload_va = None
    idx32 = idx_small = None
    if mem_idx is not None:
        sym[_match_mem_index(d, body, mem_idx, fail)] = ("idx",)
        reload_va = body[0]
    elif idx_op.reg.width == 64:
        sym[idx_op.reg.index] = ("idx",)
    elif idx_op.reg.width == 32:
        idx32 = idx_op.reg.index           # zero-extension still required
        # unsigned compare: a bound N < 2^31 also proves bit 31 clear, so a
        # sign-extending writer leaves the 64-bit register equal to the index
        if all(_upper_half_zero(d, preds, c.address, idx32, sext_ok=count <= 1 << 31) for c in cmps):
            sym[idx32] = ("idx",)          # the full 64-bit register already equals the bounded index
        copies = {_copy_before(d, preds, c.address, idx32) for c in cmps}
        if len(copies) == 1 and None not in copies:
            sym[copies.pop()] = ("idx",)   # `mov r32, idx32` before the compare: zero-extended copy
    else:
        # 8/16-bit compare: the index must be re-derived by `movzx r32, <same reg>`
        idx_small = (idx_op.reg.index, idx_op.reg.width)

    def regs(insn):
        return [o for o in insn.operands]

    from .decoder import make_register
    written = set()
    for va in body[:-1]:
        insn = d.insns[va]
        for n in insn.regs_written:
            r = make_register(n)
            if r.kind == "gpr":
                written.add(r.index)
    def base_of(reg, va):
        """Symbolic table base held in GPR `reg` at `va`: a known `lea [rip+T]`
        in the sequence, or (if untouched since the bounds check) a register
        resolved later by reaching definitions."""
        b = sym.get(reg.index) if reg is not None and reg.kind == "gpr" and reg.width == 64 else None
        if b is not None:
            return b[1] if b[0] == "base" else None
        if reg is not None and reg.kind == "gpr" and reg.width == 64 and reg.index not in written:
            nonlocal first_load
            if first_load is None:
                first_load = va
            return ("reg", reg.index)
        return None

    first_load = None             # where a deferred base register is first read

    def kill(index):
        nonlocal idx32
        if index == idx32:
            idx32 = None

    for va in body[:-1]:
        if va == reload_va:
            continue
        insn = d.insns[va]
        ops = regs(insn)
        mn = insn.mnemonic
        dst = ops[0] if ops else None
        if mn == "movzx" and len(ops) == 2 and idx_small is not None and dst.kind == "reg" \
                and dst.reg.kind == "gpr" and dst.reg.width == 32 and ops[1].kind == "reg" \
                and ops[1].reg.kind == "gpr" and not ops[1].reg.high8 \
                and (ops[1].reg.index, ops[1].reg.width) == idx_small:
            sym[dst.reg.index] = ("idx",)                 # zero-extended bounded 8/16-bit index
            if dst.reg.index == idx_small[0]:
                idx_small = None
            kill(dst.reg.index)
        elif mn == "cdqe" and (idx32 == 0 or sym.get(0) == ("idx",)) and count <= 1 << 31:
            sym[0] = ("idx",)                             # 0 <= eax < 2^31: sign-extension is exact
            kill(0)
        elif mn == "movsxd" and len(ops) == 2 and dst.kind == "reg" and dst.reg.width == 64 \
                and ops[1].kind == "reg" and ops[1].reg.width == 32 and count <= 1 << 31 \
                and (ops[1].reg.index == idx32 or sym.get(ops[1].reg.index) == ("idx",)):
            sym[dst.reg.index] = ("idx",)
            kill(dst.reg.index)
        elif mn == "mov" and len(ops) == 2 and all(o.kind == "reg" and o.reg.kind == "gpr" for o in ops) \
                and ops[0].reg.width == ops[1].reg.width and ops[0].reg.width in (32, 64):
            src = ops[1]
            src_sym = sym.get(src.reg.index)
            if dst.reg.width == 32 and idx32 is not None and src.reg.index == idx32:
                sym[dst.reg.index] = ("idx",)             # 32-bit mov zero-extends the bounded index
            elif dst.reg.width == 64 and src_sym is not None:
                sym[dst.reg.index] = src_sym
            else:
                raise fail(f"unexpected copy at 0x{va:x}")
            kill(dst.reg.index)
        elif mn == "lea" and len(ops) == 2 and dst.kind == "reg" and dst.reg.width == 64 \
                and ops[1].kind == "mem" and ops[1].mem.rip_target is not None:
            sym[dst.reg.index] = ("base", ops[1].mem.rip_target)
            kill(dst.reg.index)
        elif mn == "movsxd" and len(ops) == 2 and dst.kind == "reg" and dst.reg.width == 64 \
                and ops[1].kind == "mem" and ops[1].size == 4:
            # clang/gcc: int32 offsets relative to the table: target = T + s32[T + 4*idx]
            m = ops[1].mem
            b = base_of(m.base, va)
            i = sym.get(m.index.index) if m.index is not None and m.index.kind == "gpr" else None
            if not (b is not None and i == ("idx",) and m.scale == 4 and m.disp == 0
                    and m.segment is None and m.index.width == 64):
                raise fail(f"unexpected table load at 0x{va:x}")
            sym[dst.reg.index] = ("entry", ("rel", b))
            kill(dst.reg.index)
        elif mn == "mov" and len(ops) == 2 and dst.kind == "reg" and dst.reg.kind == "gpr" \
                and dst.reg.width == 32 and ops[1].kind == "mem" and ops[1].size == 4:
            # MSVC: uint32 RVAs indexed from the image base: target = B + u32[B + disp + 4*idx]
            m = ops[1].mem
            b = base_of(m.base, va)
            i = sym.get(m.index.index) if m.index is not None and m.index.kind == "gpr" else None
            if not (b is not None and i is not None and i[0] in ("idx", "idx2") and m.scale == 4
                    and m.segment is None and m.index.width == 64 and m.disp >= 0):
                raise fail(f"unexpected table load at 0x{va:x}")
            if i[0] == "idx2" and i[1] != b:
                raise fail(f"index table and entry table use different bases at 0x{va:x}")
            sym[dst.reg.index] = ("entry", ("rva", b, m.disp, i[2] if i[0] == "idx2" else None))
            kill(dst.reg.index)
        elif mn == "movzx" and len(ops) == 2 and dst.kind == "reg" and dst.reg.kind == "gpr" \
                and dst.reg.width == 32 and ops[1].kind == "mem" and ops[1].size == 1:
            # MSVC two-level switch: byte index table u8[B + disp + idx] selects the entry
            m = ops[1].mem
            b = base_of(m.base, va)
            i = sym.get(m.index.index) if m.index is not None and m.index.kind == "gpr" else None
            if not (b is not None and i == ("idx",) and m.scale == 1 and m.segment is None
                    and m.index.width == 64 and m.disp >= 0):
                raise fail(f"unexpected index-table load at 0x{va:x}")
            sym[dst.reg.index] = ("idx2", b, m.disp)
            kill(dst.reg.index)
        elif mn == "add" and len(ops) == 2 and all(o.kind == "reg" and o.reg.width == 64 for o in ops):
            a, b = sym.get(ops[0].reg.index), sym.get(ops[1].reg.index)
            ent, other = (a, ops[1]) if a and a[0] == "entry" else (b, ops[0]) if b and b[0] == "entry" else (None, None)
            if ent is None:
                raise fail(f"unexpected add at 0x{va:x}")
            desc = ent[1]
            if base_of(other.reg, va) != desc[1]:
                raise fail(f"unexpected add at 0x{va:x}")
            sym[ops[0].reg.index] = ("target", desc)
        else:
            raise fail(f"unexpected instruction '{insn.text}' at 0x{va:x}")

    final = sym.get(op.reg.index)
    if not final or final[0] != "target":
        raise fail("jump register is not table base + table entry")
    desc = final[1]
    if isinstance(desc[1], tuple):                     # ("reg", index): needs reaching definitions
        return PendingTable(jmp.address, desc[1][1], first_load, count, cmp.address, desc), proof
    return _table_targets(d, jmp, desc, count, cmp.address), proof


def _table_targets(d, jmp, desc, count, cmp_va):
    """Read the entries from the image (the translated code re-reads the table
    at run time and faults on any target not in this set, so a table that is
    rewritten later cannot redirect control flow). desc = ("rel", T): target = T + s32[T + 4k];
    ("rva", B, disp, bt): target = B + u32[B + disp + 4j] with j = k, or
    j = u8[B + bt + k] for a two-level (byte index) table."""
    def fail(why):
        return CFGError(f"0x{jmp.address:x}: unresolved indirect jump '{jmp.text}' ({why})")

    def read(ea, n, signed=False):
        rva = ea - d.base
        if not (0 <= rva and rva + n <= len(d.pe.image)):
            raise fail(f"table entry at 0x{ea:x} outside the image")
        return int.from_bytes(bytes(d.pe.image[rva:rva + n]), "little", signed=signed)

    targets = []
    if desc[0] == "rel":
        table = desc[1]
        for k in range(count):
            targets.append((table + read(table + 4 * k, 4, signed=True)) & ((1 << 64) - 1))
    else:
        _, base, disp, bt = desc
        table = base + disp
        js = [read(base + bt + k, 1) for k in range(count)] if bt is not None else list(range(count))
        for j in js:
            targets.append((base + read(table + 4 * j, 4)) & ((1 << 64) - 1))
    for t in targets:
        if not d.in_code(t):
            raise fail(f"table entry -> 0x{t:x} is not in an executable section")
    return JumpTable(jmp.address, table, count, tuple(targets), cmp_va)


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
