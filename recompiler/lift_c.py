"""Lift reachable x86-64 code to C that runs against runtime/x86_cpu.h.

Design (cf. N64Recomp's one-C-function-per-guest-function model, adapted to
x86-64 and Windows x64):

* every discovered guest function becomes ``static void f_<VA>(x86_state *s)``;
  its basic blocks become labels and gotos inside that function;
* guest CALL pushes the guest return VA on the *guest* stack, invokes the
  callee's C function, then verifies that the callee's guest RET popped exactly
  that VA (``s->rip``). Host return addresses never enter guest memory;
* indirect calls (registers, function-pointer tables, IAT slots) load the
  target VA from guest state/memory at run time and go through the generated
  ``exe2mac_dispatch`` switch; unknown targets fault;
* RIP-relative addresses are emitted as ``B + rva`` where ``B`` is the actual
  load base, so the code stays correct when the image is rebased;
* every instruction form is matched explicitly. Anything else raises
  ``TranslationError`` naming the address and instruction - never a no-op.
"""
from __future__ import annotations

from .cfg import Program, discover
from .decoder import Instruction, Operand

M64 = (1 << 64) - 1

SUPPORTED_IMPORTS = frozenset(("kernel32.dll", n) for n in (
    "ExitProcess", "GetStdHandle", "WriteFile", "ReadFile", "GetCommandLineA",
    "GetLastError", "SetLastError", "GetProcessHeap", "HeapAlloc", "HeapReAlloc",
    "HeapFree", "VirtualAlloc", "VirtualFree",
))

COND = {"o": 0, "no": 1, "b": 2, "ae": 3, "e": 4, "ne": 5, "be": 6, "a": 7,
        "s": 8, "ns": 9, "p": 10, "np": 11, "l": 12, "ge": 13, "le": 14, "g": 15}
COND_NAMES = ["X86_CC_O", "X86_CC_NO", "X86_CC_B", "X86_CC_AE", "X86_CC_E", "X86_CC_NE",
              "X86_CC_BE", "X86_CC_A", "X86_CC_S", "X86_CC_NS", "X86_CC_P", "X86_CC_NP",
              "X86_CC_L", "X86_CC_GE", "X86_CC_LE", "X86_CC_G"]

# Instructions that raise an exception (no SEH yet: the process ends with this status).
TRAP_STATUS = {"int3": (0x80000003, "int3: breakpoint"),                # STATUS_BREAKPOINT
               "ud2": (0xC000001D, "ud2: illegal instruction")}        # STATUS_ILLEGAL_INSTRUCTION
FAULT_INTS = {0x29: (0xC0000409, "int 0x29: __fastfail"),              # STATUS_STACK_BUFFER_OVERRUN
              0x2C: (0xC0000420, "int 0x2c: assertion failure")}       # STATUS_ASSERTION_FAILURE

BINOPS = {"add": "x86_add", "sub": "x86_sub", "and": "x86_and", "or": "x86_or", "xor": "x86_xor",
          "adc": "x86_adc", "sbb": "x86_sbb"}
SHIFTS = {"shr": "x86_shr", "shl": "x86_shl", "sal": "x86_shl", "sar": "x86_sar"}
STRING_OPS = {"rep stosb": "x86_rep_stosb", "rep movsb": "x86_rep_movsb"}

# ---- SSE / SSE2 ---------------------------------------------------------------
SSE_ARITH_SD = {"addsd": "SSE_ADD", "subsd": "SSE_SUB", "mulsd": "SSE_MUL", "divsd": "SSE_DIV"}
SSE_ARITH_SS = {"addss": "SSE_ADD", "subss": "SSE_SUB", "mulss": "SSE_MUL", "divss": "SSE_DIV"}
SSE_MOV128_ALIGNED = {"movaps", "movapd", "movdqa"}
SSE_MOV128_UNALIGNED = {"movups", "movupd", "movdqu"}
SSE_BITWISE = {"xorps": "^", "xorpd": "^", "pxor": "^", "andps": "&", "andpd": "&", "pand": "&",
               "orps": "|", "orpd": "|", "por": "|", "andnps": "&~", "andnpd": "&~", "pandn": "&~"}
SSE_CMP_SD = {"cmpeqsd": 0, "cmpltsd": 1, "cmplesd": 2, "cmpunordsd": 3,
              "cmpneqsd": 4, "cmpnltsd": 5, "cmpnlesd": 6, "cmpordsd": 7}
# Packed operations `dst = f(dst, src)` on whole XMM registers (runtime/x86_simd.h).
def _lanes(fn, sizes):
    return {f"{fn[0]}{suffix}": f"{fn[1]}(a, b, {bits})" for suffix, bits in sizes}
SIMD_BINARY = {
    **_lanes(("padd", "v_add"), (("b", 8), ("w", 16), ("d", 32), ("q", 64))),
    **_lanes(("psub", "v_sub"), (("b", 8), ("w", 16), ("d", 32), ("q", 64))),
    **_lanes(("pcmpeq", "v_cmpeq"), (("b", 8), ("w", 16), ("d", 32))),
    **_lanes(("pcmpgt", "v_cmpgt"), (("b", 8), ("w", 16), ("d", 32))),
    "pmullw": "v_mullw(a, b)", "pmuludq": "v_muludq(a, b)",
    "pminub": "v_minmax(a, b, 8, 0, 0)", "pmaxub": "v_minmax(a, b, 8, 0, 1)",
    "pminsw": "v_minmax(a, b, 16, 1, 0)", "pmaxsw": "v_minmax(a, b, 16, 1, 1)",
    "packuswb": "v_pack(a, b, 16, 1)", "packsswb": "v_pack(a, b, 16, 0)", "packssdw": "v_pack(a, b, 32, 0)",
    "punpcklbw": "v_unpack(a, b, 8, 0)", "punpckhbw": "v_unpack(a, b, 8, 1)",
    "punpcklwd": "v_unpack(a, b, 16, 0)", "punpckhwd": "v_unpack(a, b, 16, 1)",
    "punpckldq": "v_unpack(a, b, 32, 0)", "punpckhdq": "v_unpack(a, b, 32, 1)",
    "punpcklqdq": "v_unpack(a, b, 64, 0)", "punpckhqdq": "v_unpack(a, b, 64, 1)",
    "unpcklps": "v_unpack(a, b, 32, 0)", "unpckhps": "v_unpack(a, b, 32, 1)",
    "unpcklpd": "v_unpack(a, b, 64, 0)", "unpckhpd": "v_unpack(a, b, 64, 1)",
    "addps": "v_fp32(s, a, b, SSE_ADD)", "subps": "v_fp32(s, a, b, SSE_SUB)",
    "mulps": "v_fp32(s, a, b, SSE_MUL)", "divps": "v_fp32(s, a, b, SSE_DIV)",
    "addpd": "v_fp64(s, a, b, SSE_ADD)", "subpd": "v_fp64(s, a, b, SSE_SUB)",
    "mulpd": "v_fp64(s, a, b, SSE_MUL)", "divpd": "v_fp64(s, a, b, SSE_DIV)",
}
SIMD_SHIFT = {"psllw": (16, 0), "pslld": (32, 0), "psllq": (64, 0),
              "psrlw": (16, 1), "psrld": (32, 1), "psrlq": (64, 1),
              "psraw": (16, 2), "psrad": (32, 2)}
SIMD_BYTESHIFT = {"pslldq": 1, "psrldq": 0}
SIMD_SHUF_IMM = {"pshufd": "v_pshufd(b, {imm}u)", "pshuflw": "v_pshuflw(b, {imm}u)",
                 "pshufhw": "v_pshufhw(b, {imm}u)", "shufps": "v_shufps(a, b, {imm}u)"}
SIMD_MOVMSK = {"pmovmskb": 8, "movmskps": 32, "movmskpd": 64}

SSE_MNEMONICS = (set(SSE_ARITH_SD) | set(SSE_ARITH_SS) | SSE_MOV128_ALIGNED | SSE_MOV128_UNALIGNED
                 | set(SSE_BITWISE) | set(SSE_CMP_SD) | set(SIMD_BINARY) | set(SIMD_SHIFT)
                 | set(SIMD_BYTESHIFT) | set(SIMD_SHUF_IMM) | set(SIMD_MOVMSK) | {"cvtsi2ss"}
                 | {"movsd", "movss", "movd", "movq", "sqrtsd", "minsd", "maxsd", "ucomisd", "comisd",
                    "cmpsd", "cvtsd2ss", "cvtss2sd", "cvtsi2sd", "cvttsd2si", "cvtsd2si"})
CMPOPS = {"cmp": "x86_sub", "test": "x86_and"}
UNOPS = {"inc": "x86_inc", "dec": "x86_dec", "neg": "x86_neg"}


class TranslationError(RuntimeError):
    pass


def _err(insn: Instruction, why: str) -> TranslationError:
    return TranslationError(f"0x{insn.address:x}: {why}: '{insn.text}' (bytes {insn.encoding.hex()})")


class _Fn:
    """Per-instruction emission context."""

    def __init__(self, lifter, insn: Instruction):
        self.l = lifter
        self.insn = insn
        self.lines: list[str] = []

    # ---- operands ----------------------------------------------------------
    def check_prefixes(self):
        p = self.insn.prefixes
        mn = self.insn.mnemonic
        if 0x67 in p:
            raise _err(self.insn, "32-bit address-size override is not supported")
        if mn in STRING_OPS:
            if any(x in (0xF0, 0xF2) for x in p):
                raise _err(self.insn, "LOCK/REPNE on a string instruction is not supported")
            for op in self.insn.operands:      # implicit [rdi]/[rsi] (ES/DS are flat in 64-bit mode)
                if op.kind == "mem" and (op.mem.base is None or op.mem.base.name not in ("rdi", "rsi")
                                         or op.mem.index is not None or op.mem.disp):
                    raise _err(self.insn, "unexpected string-instruction operand")
                if op.kind == "mem" and op.mem.segment is not None and op.mem.segment.name in ("fs", "gs"):
                    raise _err(self.insn, f"segment override {op.mem.segment.name} is not supported")
            return
        if any(x in (0xF0, 0xF2, 0xF3) for x in p):
            raise _err(self.insn, "LOCK/REP prefixes are not supported")
        for op in self.insn.operands:
            if op.kind == "mem" and op.mem.segment is not None:
                raise _err(self.insn, f"segment override {op.mem.segment.name} is not supported")
            if op.kind == "reg" and op.reg.kind != "gpr" and not (op.reg.kind == "xmm" and mn in SSE_MNEMONICS):
                raise _err(self.insn, f"register {op.reg.name} is not supported")

    def ea(self, op: Operand) -> str:
        m = op.mem
        parts = []
        if m.base is not None:
            if m.base.kind == "rip":
                rva = m.rip_target - self.l.pref_base
                if not 0 <= rva < self.l.image_size:
                    raise _err(self.insn, "RIP-relative target outside the image")
                return f"(B + 0x{rva:x}ull)"
            if m.base.kind != "gpr" or m.base.width != 64:
                raise _err(self.insn, "non-64-bit base register")
            parts.append(f"s->gpr[{m.base.index}]")
        if m.index is not None:
            if m.index.kind != "gpr" or m.index.width != 64:
                raise _err(self.insn, "non-64-bit index register")
            if m.scale not in (1, 2, 4, 8):
                raise _err(self.insn, "invalid scale")
            parts.append(f"s->gpr[{m.index.index}]" + (f" * {m.scale}u" if m.scale != 1 else ""))
        if m.disp or not parts:
            if not parts:
                raise _err(self.insn, "absolute (no base/index) memory operand is not supported")
            parts.append(f"0x{m.disp & M64:x}ull")
        return "(" + " + ".join(parts) + ")"

    def read(self, op: Operand, ea_var: str | None = None) -> str:
        if op.kind == "imm":
            return f"0x{op.imm:x}ull"
        if op.kind == "reg":
            r = op.reg
            if r.width != op.bits:
                raise _err(self.insn, "register/operand width mismatch")
            return f"x86_get(s, {r.index}, {r.width}, {int(r.high8)})"
        if op.size not in (1, 2, 4, 8):
            raise _err(self.insn, f"memory operand size {op.size}")
        return f"guest_ld{op.bits}(s->mem, {ea_var or self.ea(op)})"

    def write(self, op: Operand, value: str, ea_var: str | None = None) -> str:
        if op.kind == "reg":
            r = op.reg
            if r.width != op.bits:
                raise _err(self.insn, "register/operand width mismatch")
            return f"x86_set(s, {r.index}, {r.width}, {int(r.high8)}, {value});"
        if op.kind == "mem":
            if op.size not in (1, 2, 4, 8):
                raise _err(self.insn, f"memory operand size {op.size}")
            return f"guest_st{op.bits}(s->mem, {ea_var or self.ea(op)}, {value});"
        raise _err(self.insn, "cannot write to an immediate")

    def need(self, n):
        if len(self.insn.operands) != n:
            raise _err(self.insn, f"expected {n} operands")
        return self.insn.operands

    def emit(self, line: str):
        self.lines.append(line)


class Lifter:
    def __init__(self, pe, program: Program, trap_unsupported: bool = False):
        self.trap_unsupported = trap_unsupported
        self.trapped: list[Instruction] = []
        self.pe = pe
        self.prog = program
        self.pref_base = pe.image_base
        self.image_size = pe.size_of_image
        self.functions = program.functions
        self.out: list[str] = []

    # ---- helpers -----------------------------------------------------------
    def rva(self, va: int) -> int:
        r = va - self.pref_base
        if not 0 <= r < self.image_size:
            raise TranslationError(f"address 0x{va:x} outside the image")
        return r

    def va_expr(self, va: int) -> str:
        return f"(B + 0x{self.rva(va):x}ull)"

    @staticmethod
    def fname(va: int) -> str:
        return f"f_{va:x}"

    @staticmethod
    def label(va: int) -> str:
        return f"L_{va:x}"

    def check_relocations(self):
        exec_ranges = [(s.vaddr, s.vaddr + max(s.vsize, s.raw_size)) for s in self.pe.sections if s.executable]
        for r in self.pe.relocs:
            if any(lo <= r < hi for lo, hi in exec_ranges):
                raise TranslationError(
                    f"relocation at RVA 0x{r:x} patches code; absolute addresses in instructions are not supported")

    def check_imports(self):
        for _, dll, name in self.pe.imports:
            if (dll, name) not in SUPPORTED_IMPORTS:
                raise TranslationError(f"unsupported import {dll}!{name}")

    # ---- instruction lowering ----------------------------------------------
    def lift_or_trap(self, insn: Instruction, fn_entry: int, block_succ: list[int]) -> list[str]:
        """Lift one instruction. With ``trap_unsupported``, an instruction form
        the translator does not implement becomes a run-time #UD
        (STATUS_ILLEGAL_INSTRUCTION) at that address instead of a translation
        error, and is listed in ``self.trapped``. Control-flow instructions are
        never trapped: they define the CFG."""
        try:
            return self.lift_insn(insn, fn_entry, block_succ)
        except TranslationError:
            if not self.trap_unsupported or insn.flow != "none":
                raise
        self.trapped.append(insn)
        text = insn.text.replace("\\", "\\\\").replace('"', '\\"')
        return [f"/* 0x{insn.address:x}: {insn.text} -- NOT IMPLEMENTED: run-time #UD */",
                f"s->rip = {self.va_expr(insn.address)};",
                f'exe2mac_raise(s, 0xC000001Du, "instruction not implemented by exe2mac: {text}");']

    def lift_insn(self, insn: Instruction, fn_entry: int, block_succ: list[int]) -> list[str]:
        f = _Fn(self, insn)
        mn = insn.mnemonic
        if mn == "nop":                     # multi-byte NOPs never access their memory operand
            return [f"/* 0x{insn.address:x}: nop */"]
        f.check_prefixes()
        ops = insn.operands
        f.emit(f"/* 0x{insn.address:x}: {insn.text} */")

        def with_ea(op):
            if op.kind == "mem":
                f.emit(f"ea = {f.ea(op)};")
                return "ea"
            return None

        if mn in ("mov", "movabs"):
            dst, src = f.need(2)
            if dst.kind == "mem" and src.kind == "mem":
                raise _err(insn, "memory-to-memory mov")
            if src.size != dst.size:
                raise _err(insn, "mov operand sizes differ")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f.write(dst, f.read(src)))
        elif mn == "movsxd":
            dst, src = f.need(2)
            if not (dst.kind == "reg" and dst.size == 8 and src.size == 4):
                raise _err(insn, "only movsxd r64, r/m32 is supported")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f.write(dst, f"x86_sext({f.read(src)}, 32)"))
        elif mn == "lea":
            dst, src = f.need(2)
            if dst.kind != "reg" or src.kind != "mem" or dst.size not in (2, 4, 8):
                raise _err(insn, "invalid lea form")
            f.emit(f.write(dst, f.ea(src)))          # x86_set masks/zero-extends to the destination width
        elif mn in BINOPS:
            dst, src = f.need(2)
            if src.size != dst.size:
                raise _err(insn, "operand sizes differ")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            e = with_ea(dst)
            f.emit(f"t = {BINOPS[mn]}(s, {f.read(dst, e)}, {f.read(src)}, {dst.bits});")
            f.emit(f.write(dst, "t", e))
        elif mn in CMPOPS:
            a, b = f.need(2)
            if a.size != b.size:
                raise _err(insn, "operand sizes differ")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f"(void){CMPOPS[mn]}(s, {f.read(a)}, {f.read(b)}, {a.bits});")
        elif mn in UNOPS:
            (dst,) = f.need(1)
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            e = with_ea(dst)
            f.emit(f"t = {UNOPS[mn]}(s, {f.read(dst, e)}, {dst.bits});")
            f.emit(f.write(dst, "t", e))
        elif mn in SHIFTS:
            dst, cnt = f.need(2)
            if not (cnt.kind == "imm" or (cnt.kind == "reg" and cnt.reg.name == "cl")):
                raise _err(insn, "shift count must be imm8 or CL")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            e = with_ea(dst)
            f.emit(f"t = {SHIFTS[mn]}(s, {f.read(dst, e)}, {f.read(cnt)}, {dst.bits});")
            f.emit(f.write(dst, "t", e))
        elif mn == "bt":
            base, off = f.need(2)
            if base.size not in (2, 4, 8) or off.kind == "mem" or (off.kind == "reg" and off.size != base.size):
                raise _err(insn, "invalid bt form")
            if base.kind == "mem" and off.kind != "imm":
                raise _err(insn, "bt with a memory bit string and register offset is not supported")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f"x86_bt(s, {f.read(base)}, {f.read(off)}, {base.bits});")
        elif mn in ("movzx", "movsx"):
            dst, src = f.need(2)
            if dst.kind != "reg" or dst.size not in (2, 4, 8) or src.size not in (1, 2) or src.size >= dst.size:
                raise _err(insn, f"invalid {mn} form")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            v = f.read(src) if mn == "movzx" else f"x86_sext({f.read(src)}, {src.bits})"
            f.emit(f.write(dst, v))
        elif mn == "not":
            (dst,) = f.need(1)
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            e = with_ea(dst)
            f.emit(f"t = x86_not({f.read(dst, e)}, {dst.bits});")
            f.emit(f.write(dst, "t", e))
        elif mn.startswith("set") and mn[3:] in COND:
            (dst,) = f.need(1)
            if dst.size != 1:
                raise _err(insn, "setcc destination must be 8-bit")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f.write(dst, f"(uint64_t)x86_cond(s, {COND_NAMES[COND[mn[3:]]]})"))
        elif mn == "xchg":
            a, b = f.need(2)
            if a.size != b.size or a.kind == "imm" or b.kind == "imm" or (a.kind == "mem" and b.kind == "mem"):
                raise _err(insn, "invalid xchg form")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            ea_a = with_ea(a)
            ea_b = with_ea(b)
            f.emit(f"t = {f.read(a, ea_a)};")
            f.emit(f"{{ uint64_t u = {f.read(b, ea_b)};")
            f.emit("  " + f.write(a, "u", ea_a))
            f.emit("  " + f.write(b, "t", ea_b) + " }")
        elif mn in STRING_OPS:
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f"{STRING_OPS[mn]}(s);")
        elif mn == "mul":
            (src,) = f.need(1)
            if src.size not in (4, 8):
                raise _err(insn, "mul width")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f"x86_mul(s, {f.read(src)}, {src.bits});")
        elif mn == "imul":
            if len(ops) == 2:
                dst, src = ops
                if dst.kind != "reg" or dst.size not in (2, 4, 8) or src.size != dst.size:
                    raise _err(insn, "invalid two-operand imul")
                f.emit(f"s->rip = {self.va_expr(insn.address)};")
                f.emit(f"t = x86_imul2(s, {f.read(dst)}, {f.read(src)}, {dst.bits});")
                f.emit(f.write(dst, "t"))
            elif len(ops) == 3:
                dst, src, imm = ops
                if dst.kind != "reg" or imm.kind != "imm" or dst.size not in (2, 4, 8):
                    raise _err(insn, "invalid three-operand imul")
                f.emit(f"s->rip = {self.va_expr(insn.address)};")
                f.emit(f"t = x86_imul2(s, {f.read(src)}, {f.read(imm)}, {dst.bits});")
                f.emit(f.write(dst, "t"))
            else:
                raise _err(insn, "one-operand imul is not supported")
        elif mn in ("idiv", "div"):
            (src,) = f.need(1)
            if src.size not in (4, 8):
                raise _err(insn, f"{mn} width")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f"x86_{mn}(s, {f.read(src)}, {src.bits});")
        elif mn == "cdq":
            f.need(0)
            f.emit("x86_cdq(s);")
        elif mn == "cqo":
            f.need(0)
            f.emit("x86_cqo(s);")
        elif mn in ("cdqe", "cwde"):
            f.need(0)
            f.emit(f"x86_{mn}(s);")
        elif mn.startswith("cmov") and mn[4:] in COND:
            dst, src = f.need(2)
            if dst.kind != "reg" or dst.size not in (2, 4, 8) or src.size != dst.size:
                raise _err(insn, "invalid cmov form")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            # source is read unconditionally (a memory source may fault even if not taken);
            # a 32-bit destination is zero-extended whether or not the move happens
            f.emit(f"t = {f.read(src)};")
            f.emit(f.write(dst, f"x86_cond(s, {COND_NAMES[COND[mn[4:]]]}) ? t : {f.read(dst)}"))
        elif mn in SSE_MNEMONICS and any(o.kind == "reg" and o.reg.kind == "xmm" for o in ops):
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            self.lift_sse(f, insn)
        elif mn in ("ldmxcsr", "stmxcsr"):
            (m32,) = f.need(1)
            if m32.kind != "mem" or m32.size != 4:
                raise _err(insn, f"{mn} needs an m32 operand")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            if mn == "ldmxcsr":
                f.emit(f"sse_ldmxcsr(s, (uint32_t)guest_ld32(s->mem, {f.ea(m32)}));")
            else:
                f.emit(f"guest_st32(s->mem, {f.ea(m32)}, s->mxcsr);")
        elif mn == "push":
            (src,) = f.need(1)
            if src.size != 8:
                raise _err(insn, "only 64-bit push is supported")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f"t = {f.read(src)};")         # value (incl. RSP) is read before the decrement
            f.emit("x86_push64(s, t);")
        elif mn == "pop":
            (dst,) = f.need(1)
            if dst.kind != "reg" or dst.size != 8:
                raise _err(insn, "only pop r64 is supported")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit("t = x86_pop64(s);")
            f.emit(f.write(dst, "t"))
        elif mn == "jmp" and insn.direct_target is None and insn.address not in self.prog.jump_tables:
            # tail call through the IAT or a function pointer: hand the target to the
            # trampoline of our host caller (the guest stack is already set up)
            (op,) = f.need(1)
            if op.size != 8:
                raise _err(insn, "jmp target must be 64-bit")
            if insn.address in self.prog.dynamic_tail_jumps:
                f.emit(f"/* dynamic tail call ({self.prog.dynamic_tail_jumps[insn.address]}) */")
            elif self.cur_terms.get(insn.address) != "import_tailcall":
                raise _err(insn, "indirect jmp")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f"t = {f.read(op)};")
            f.emit("exe2mac_tail(s, t);")
            f.emit("return;")
        elif mn == "jmp" and insn.direct_target is None:
            jt = self.prog.jump_tables[insn.address]
            (op,) = f.need(1)
            # The table load and add already ran as ordinary instructions; only
            # targets proven by the CFG are reachable, anything else faults.
            f.emit(f"t = {f.read(op)};")
            f.emit("switch (t - B) {")
            for tgt in sorted(set(jt.targets)):
                if tgt not in self.cur_blocks:
                    raise _err(insn, f"jump-table target 0x{tgt:x} is not a block of this function")
                f.emit(f"case 0x{self.rva(tgt):x}ull: goto {self.label(tgt)};")
            f.emit(f"default: s->rip = {self.va_expr(insn.address)}; "
                   "exe2mac_fault(s, \"jump-table target outside the analysed table\", t);")
            f.emit("}")
        elif mn == "jmp":
            if insn.direct_target not in self.cur_blocks:
                raise _err(insn, "jmp leaves the current function (tail call)")
            f.emit(f"goto {self.label(insn.direct_target)};")
        elif mn.startswith("j") and mn[1:] in COND:
            if insn.direct_target is None:
                raise _err(insn, "indirect conditional jump")
            f.emit(f"if (x86_cond(s, {COND_NAMES[COND[mn[1:]]]})) goto {self.label(insn.direct_target)};")
            f.emit(f"goto {self.label(insn.next)};")
        elif mn == "call":
            self.lift_call(f, insn)
        elif mn == "ret":
            if ops:
                raise _err(insn, "ret imm16 is not supported")
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit("s->rip = x86_pop64(s);")
            f.emit("return;")
        elif mn == "cpuid":
            f.emit("x86_cpuid(s);")
        elif mn == "xgetbv":
            # CPUID reports OSXSAVE = 0, so XGETBV raises #UD (SDM: CR4.OSXSAVE = 0)
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit('exe2mac_raise(s, 0xC000001Du, "xgetbv: #UD (the virtual CPU reports OSXSAVE = 0)");')
        elif mn in ("int3", "ud2") or (mn == "int" and ops and ops[0].kind == "imm" and ops[0].imm in FAULT_INTS):
            # Without SEH these end the process with the Windows status of the exception.
            status, what = (TRAP_STATUS[mn] if mn != "int" else FAULT_INTS[ops[0].imm])
            f.emit(f"s->rip = {self.va_expr(insn.address)};")
            f.emit(f'exe2mac_raise(s, 0x{status:08X}u, "{what}");')
        else:
            raise _err(insn, "unsupported instruction")
        return f.lines

    # ---- SSE ------------------------------------------------------------------
    def lift_sse(self, f: _Fn, insn: Instruction):
        mn, ops = insn.mnemonic, insn.operands

        def xmm(op):
            if op.kind != "reg" or op.reg.kind != "xmm":
                raise _err(insn, "expected an XMM register operand")
            return op.reg.index

        def src64(op):            # scalar double source: xmm low qword or m64
            if op.kind == "reg":
                return f"s->xmm[{xmm(op)}].lo"
            if op.kind == "mem" and op.size == 8:
                return f"guest_ld64(s->mem, {f.ea(op)})"
            raise _err(insn, "expected xmm or m64 source")

        def src32(op):            # scalar float source: xmm low dword or m32
            if op.kind == "reg":
                return f"(uint32_t)s->xmm[{xmm(op)}].lo"
            if op.kind == "mem" and op.size == 4:
                return f"(uint32_t)guest_ld32(s->mem, {f.ea(op)})"
            raise _err(insn, "expected xmm or m32 source")

        def src128(op, aligned):  # into locals lo/hi
            if op.kind == "reg":
                f.emit(f"{{ uint64_t lo = s->xmm[{xmm(op)}].lo, hi = s->xmm[{xmm(op)}].hi;")
            elif op.kind == "mem" and op.size == 16:
                f.emit(f"{{ uint64_t lo, hi; sse_ld128(s, {f.ea(op)}, {int(aligned)}, &lo, &hi);")
            else:
                raise _err(insn, "expected xmm or m128 source")

        if mn in SSE_ARITH_SD:                      # low qword = op(dst, src); high preserved
            dst, src = f.need(2)
            d = xmm(dst)
            f.emit(f"s->xmm[{d}].lo = sse_f64_arith(s, s->xmm[{d}].lo, {src64(src)}, {SSE_ARITH_SD[mn]});")
        elif mn in SSE_ARITH_SS:                    # low dword only
            dst, src = f.need(2)
            d = xmm(dst)
            f.emit(f"xmm_set_lo32(s, {d}, sse_f32_arith(s, (uint32_t)s->xmm[{d}].lo, {src32(src)}, {SSE_ARITH_SS[mn]}));")
        elif mn == "sqrtsd":
            dst, src = f.need(2)
            f.emit(f"s->xmm[{xmm(dst)}].lo = sse_f64_sqrt(s, {src64(src)});")
        elif mn in ("minsd", "maxsd"):
            dst, src = f.need(2)
            d = xmm(dst)
            f.emit(f"s->xmm[{d}].lo = sse_f64_{mn[:3]}(s, s->xmm[{d}].lo, {src64(src)});")
        elif mn in ("ucomisd", "comisd"):
            a, b = f.need(2)
            f.emit(f"sse_f64_{'ucomi' if mn == 'ucomisd' else 'comi'}(s, s->xmm[{xmm(a)}].lo, {src64(b)});")
        elif mn in SSE_CMP_SD or mn == "cmpsd":
            if mn == "cmpsd":
                dst, src, imm = f.need(3)
                if imm.kind != "imm" or imm.imm > 7:
                    raise _err(insn, "cmpsd predicate must be 0..7")
                pred = imm.imm
            else:
                dst, src = f.need(2)
                pred = SSE_CMP_SD[mn]
            d = xmm(dst)
            f.emit(f"s->xmm[{d}].lo = sse_f64_cmp(s, s->xmm[{d}].lo, {src64(src)}, {pred}u);")
        elif mn == "movsd":
            dst, src = f.need(2)
            if dst.kind == "reg" and src.kind == "mem":       # load: zero the high qword
                f.emit(f"xmm_set_lo64_zero_hi(s, {xmm(dst)}, {src64(src)});")
            elif dst.kind == "mem" and src.kind == "reg":
                if dst.size != 8:
                    raise _err(insn, "movsd store must be m64")
                f.emit(f"guest_st64(s->mem, {f.ea(dst)}, s->xmm[{xmm(src)}].lo);")
            elif dst.kind == "reg" and src.kind == "reg":     # register form merges the low qword
                f.emit(f"xmm_set_lo64(s, {xmm(dst)}, s->xmm[{xmm(src)}].lo);")
            else:
                raise _err(insn, "invalid movsd form")
        elif mn == "movss":
            dst, src = f.need(2)
            if dst.kind == "reg" and src.kind == "mem":
                f.emit(f"xmm_set_lo32_zero_rest(s, {xmm(dst)}, {src32(src)});")
            elif dst.kind == "mem" and src.kind == "reg":
                if dst.size != 4:
                    raise _err(insn, "movss store must be m32")
                f.emit(f"guest_st32(s->mem, {f.ea(dst)}, (uint32_t)s->xmm[{xmm(src)}].lo);")
            elif dst.kind == "reg" and src.kind == "reg":
                f.emit(f"xmm_set_lo32(s, {xmm(dst)}, (uint32_t)s->xmm[{xmm(src)}].lo);")
            else:
                raise _err(insn, "invalid movss form")
        elif mn in ("movd", "movq"):
            dst, src = f.need(2)
            width = 32 if mn == "movd" else 64
            if dst.kind == "reg" and dst.reg.kind == "xmm":   # into xmm: zero the rest
                if src.kind == "reg" and src.reg.kind == "gpr" and src.reg.width == width:
                    v = f.read(src)
                elif src.kind == "mem" and src.size == width // 8:
                    v = f.read(src)
                elif src.kind == "reg" and src.reg.kind == "xmm" and mn == "movq":
                    v = f"s->xmm[{xmm(src)}].lo"
                else:
                    raise _err(insn, f"invalid {mn} form")
                f.emit(f"xmm_set_lo64_zero_hi(s, {xmm(dst)}, {v});")
            elif src.kind == "reg" and src.reg.kind == "xmm":  # out of xmm
                v = f"s->xmm[{xmm(src)}].lo" + (" & 0xffffffffu" if width == 32 else "")
                if dst.kind == "reg" and dst.reg.kind == "gpr" and dst.reg.width == width:
                    f.emit(f.write(dst, v))                   # 32-bit GPR write zero-extends
                elif dst.kind == "mem" and dst.size == width // 8:
                    f.emit(f.write(dst, v))
                else:
                    raise _err(insn, f"invalid {mn} form")
            else:
                raise _err(insn, f"invalid {mn} form")
        elif mn in SSE_MOV128_ALIGNED or mn in SSE_MOV128_UNALIGNED:
            dst, src = f.need(2)
            aligned = mn in SSE_MOV128_ALIGNED
            if dst.kind == "reg":
                src128(src, aligned)
                f.emit(f"  s->xmm[{xmm(dst)}].lo = lo; s->xmm[{xmm(dst)}].hi = hi; }}")
            elif dst.kind == "mem" and src.kind == "reg" and dst.size == 16:
                f.emit(f"x86_st128(s, {xmm(src)}, {f.ea(dst)}, {int(aligned)});")
            else:
                raise _err(insn, f"invalid {mn} form")
        elif mn in SSE_BITWISE:
            dst, src = f.need(2)
            d = xmm(dst)
            src128(src, True)                       # legacy-SSE m128 operands must be aligned
            o = SSE_BITWISE[mn]
            if o == "&~":
                f.emit(f"  s->xmm[{d}].lo = ~s->xmm[{d}].lo & lo; s->xmm[{d}].hi = ~s->xmm[{d}].hi & hi; }}")
            else:
                f.emit(f"  s->xmm[{d}].lo {o}= lo; s->xmm[{d}].hi {o}= hi; }}")
        elif mn in SIMD_BINARY:                     # legacy SSE: m128 operand must be 16-byte aligned
            dst, src = f.need(2)
            d = xmm(dst)
            src128(src, True)
            f.emit(f"  v128 a = v_xmm(s, {d}), b = {{ lo, hi }};")
            f.emit(f"  v_set_xmm(s, {d}, {SIMD_BINARY[mn]}); }}")
        elif mn in SIMD_SHIFT:
            dst, cnt = f.need(2)
            d = xmm(dst)
            bits, kind = SIMD_SHIFT[mn]
            if cnt.kind == "imm":
                f.emit(f"v_set_xmm(s, {d}, v_shift(v_xmm(s, {d}), {cnt.imm}u, {bits}, {kind}));")
            else:                                   # count = low qword of xmm/m128
                src128(cnt, True)
                f.emit(f"  (void)hi; v_set_xmm(s, {d}, v_shift(v_xmm(s, {d}), lo, {bits}, {kind})); }}")
        elif mn in SIMD_BYTESHIFT:
            dst, cnt = f.need(2)
            if cnt.kind != "imm":
                raise _err(insn, f"{mn} count must be an immediate")
            d = xmm(dst)
            f.emit(f"v_set_xmm(s, {d}, v_byteshift(v_xmm(s, {d}), {cnt.imm}u, {SIMD_BYTESHIFT[mn]}));")
        elif mn in SIMD_SHUF_IMM:
            dst, src, imm = f.need(3)
            if imm.kind != "imm":
                raise _err(insn, f"{mn} needs an immediate")
            d = xmm(dst)
            src128(src, True)
            f.emit(f"  v128 a = v_xmm(s, {d}), b = {{ lo, hi }}; (void)a;")
            f.emit(f"  v_set_xmm(s, {d}, {SIMD_SHUF_IMM[mn].format(imm=imm.imm)}); }}")
        elif mn in SIMD_MOVMSK:
            dst, src = f.need(2)
            if dst.kind != "reg" or dst.reg.kind != "gpr" or dst.reg.width not in (32, 64):
                raise _err(insn, f"{mn} destination must be a 32/64-bit GPR")
            f.emit(f.write(dst, f"v_movmsk(v_xmm(s, {xmm(src)}), {SIMD_MOVMSK[mn]})"))
        elif mn == "cvtsi2ss":
            dst, src = f.need(2)
            if src.kind not in ("reg", "mem") or src.size not in (4, 8) or (src.kind == "reg" and src.reg.kind != "gpr"):
                raise _err(insn, "cvtsi2ss source must be r/m32 or r/m64")
            f.emit(f"xmm_set_lo32(s, {xmm(dst)}, sse_cvtsi2ss(s, {f.read(src)}, {src.bits}));")
        elif mn == "cvtsd2ss":
            dst, src = f.need(2)
            f.emit(f"xmm_set_lo32(s, {xmm(dst)}, sse_cvtsd2ss(s, {src64(src)}));")
        elif mn == "cvtss2sd":
            dst, src = f.need(2)
            f.emit(f"xmm_set_lo64(s, {xmm(dst)}, sse_cvtss2sd(s, {src32(src)}));")
        elif mn == "cvtsi2sd":
            dst, src = f.need(2)
            if src.kind not in ("reg", "mem") or src.size not in (4, 8) or (src.kind == "reg" and src.reg.kind != "gpr"):
                raise _err(insn, "cvtsi2sd source must be r/m32 or r/m64")
            f.emit(f"xmm_set_lo64(s, {xmm(dst)}, sse_cvtsi2sd(s, {f.read(src)}, {src.bits}));")
        elif mn in ("cvttsd2si", "cvtsd2si"):
            dst, src = f.need(2)
            if dst.kind != "reg" or dst.reg.kind != "gpr" or dst.reg.width not in (32, 64):
                raise _err(insn, "cvttsd2si destination must be r32 or r64")
            f.emit(f.write(dst, f"sse_{mn}(s, {src64(src)}, {dst.reg.width})"))
        else:
            raise _err(insn, "unsupported SSE instruction")

    def lift_call(self, f: _Fn, insn: Instruction):
        ret = self.va_expr(insn.next)
        site = next((c for c in self.prog.call_sites if c.address == insn.address), None)
        if site is None:
            raise _err(insn, "call site missing from CFG")
        f.emit(f"s->rip = {self.va_expr(insn.address)};")
        if insn.direct_target is not None:
            if insn.direct_target not in self.functions:
                raise _err(insn, "direct call to an undiscovered function")
            f.emit(f"x86_push64(s, {ret});")
            f.emit(f"{self.fname(insn.direct_target)}(s);")
            f.emit("exe2mac_run_tail(s);")
        else:
            (op,) = f.need(1)
            if op.size != 8:
                raise _err(insn, "call target must be 64-bit")
            f.emit(f"t = {f.read(op)};")           # target is evaluated before the push
            f.emit(f"x86_push64(s, {ret});")
            f.emit("exe2mac_dispatch(s, t);")
            f.emit("exe2mac_run_tail(s);")
        if not site.returns:
            f.emit(f"exe2mac_noreturn_returned(s, {self.va_expr(insn.address)});")
        else:
            f.emit(f"if (s->rip != {ret}) exe2mac_bad_return(s, {ret});")

    # ---- function / program emission --------------------------------------
    def lift_function(self, fn) -> list[str]:
        self.cur_blocks = fn.blocks
        self.cur_terms = {b.instructions[-1].address: b.terminator for b in fn.blocks.values()}
        lines = [f"static void {self.fname(fn.entry)}(x86_state *s) {{",
                 "    uint64_t t, ea;",
                 "    (void)t; (void)ea;",
                 f"    goto {self.label(fn.entry)};"]
        for start in sorted(fn.blocks):
            b = fn.blocks[start]
            lines.append(f"{self.label(start)}:")
            for insn in b.instructions:
                for l in self.lift_or_trap(insn, fn.entry, b.successors):
                    lines.append("    " + l)
            last = b.instructions[-1]
            if b.terminator in ("fallthrough", "call"):
                if len(b.successors) != 1:
                    raise TranslationError(f"block 0x{start:x}: fall-through without a single successor")
                lines.append(f"    goto {self.label(b.successors[0])};")
            elif b.terminator == "call_noreturn":
                pass                                 # call emission already ends in a fault
            elif b.terminator in ("ret", "jump", "cond", "jump_table", "import_tailcall", "tailcall_dynamic", "trap"):
                pass
            else:
                raise TranslationError(f"block 0x{start:x}: unsupported terminator {b.terminator} at 0x{last.address:x}")
        lines.append("}")
        return lines

    def emit_image(self) -> list[str]:
        pe = self.pe
        img = bytes(pe.image)
        out = [f"const uint32_t exe2mac_image_size = 0x{pe.size_of_image:x}u;",
               f"const uint32_t exe2mac_headers_size = 0x{pe.size_of_headers:x}u;",
               f"const uint64_t exe2mac_preferred_base = 0x{pe.image_base:x}ull;",
               f"const uint32_t exe2mac_entry_rva = 0x{pe.entry_rva:x}u;",
               "const uint8_t exe2mac_image_init[] = {"]
        for i in range(0, len(img), 16):
            out.append("    " + ",".join(f"0x{b:02x}" for b in img[i:i + 16]) + ",")
        out.append("};")
        align = pe.section_alignment or 0x1000
        out.append("const exe2mac_section exe2mac_sections[] = {")
        n = 0
        for s in pe.sections:
            size = max(s.vsize, 1)
            size = (size + align - 1) // align * align
            size = min(size, pe.size_of_image - s.vaddr)
            perms = ["GUEST_PERM_R"] if s.chars & 0x40000000 else []
            if s.chars & 0x80000000:
                perms.append("GUEST_PERM_W")
            if not perms:
                raise TranslationError(f"section {s.name} is neither readable nor writable")
            out.append(f'    {{0x{s.vaddr:x}u, 0x{size:x}u, {" | ".join(perms)}, "{s.name}"}},')
            n += 1
        out.append("};")
        out.append(f"const unsigned exe2mac_nsections = {n}u;")
        out.append("const uint32_t exe2mac_relocs[] = {" + ", ".join(f"0x{r:x}u" for r in pe.relocs) + ("" if pe.relocs else "0") + "};")
        out.append(f"const unsigned exe2mac_nrelocs = {len(pe.relocs)}u;")
        out.append("const exe2mac_import exe2mac_imports[] = {")
        for slot, dll, name in pe.imports:
            out.append(f'    {{0x{slot:x}u, "{dll}", "{name}"}},')
        if not pe.imports:
            out.append("    {0, 0, 0},")
        out.append("};")
        out.append(f"const unsigned exe2mac_nimports = {len(pe.imports)}u;")
        return out

    def emit(self) -> str:
        self.check_imports()
        self.check_relocations()
        L = ["/* Generated by exe2mac (static recompilation of a PE32+ x86-64 image).",
             " * Do not edit. Guest state lives in x86_state; see runtime/x86_cpu.h. */",
             '#include "runtime/exe2mac_rt.h"',
             '#include "runtime/x86_simd.h"',
             "",
             "#define B g_exe2mac_base",
             ""]
        L += self.emit_image()
        L.append("")
        bodies, skipped = {}, {}
        for entry in sorted(self.functions):
            try:
                bodies[entry] = self.lift_function(self.functions[entry])
            except TranslationError as exc:
                # A candidate root found only through `lea [rip + code]` may be data
                # or unsupported code that is never executed: leave it out of the
                # dispatcher, so calling it faults. Every other function must lift.
                if entry not in self.prog.soft_roots:
                    raise
                skipped[entry] = str(exc)
        for entry, why in sorted(skipped.items()):
            L.append(f"/* candidate code pointer 0x{entry:x} not translated: {why} */")
        for entry in sorted(bodies):
            L.append(f"static void {self.fname(entry)}(x86_state *s);")
        L.append("")
        for entry in sorted(bodies):
            L += bodies[entry]
            L.append("")
        L.append("void exe2mac_dispatch(x86_state *s, uint64_t target) {")
        L.append("    switch (target - B) {")
        for entry in sorted(bodies):
            L.append(f"    case 0x{self.rva(entry):x}ull: {self.fname(entry)}(s); return;")
        L.append("    default: exe2mac_dispatch_external(s, target); return;")
        L.append("    }")
        L.append("}")
        return "\n".join(L) + "\n"


def lift_program(pe, strict_indirect_jumps: bool = False, trap_unsupported: bool = False) -> str:
    """Discover reachable code and return the generated C translation unit."""
    return Lifter(pe, discover(pe, strict_indirect_jumps=strict_indirect_jumps),
                  trap_unsupported=trap_unsupported).emit()
