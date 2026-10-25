"""Structured x86-64 decoder built on Capstone (BSD-3-Clause, used as a dependency).

This module turns raw bytes into typed instructions and operands. It does not
assign semantics; it only describes what was encoded. Everything downstream
(CFG discovery, lifting, code generation) consumes these objects instead of
parsing disassembler text.

Fail-closed rules:
* if Capstone is not installed, ``DecoderUnavailable`` is raised;
* undecodable bytes raise ``DecodeError`` with the faulting address;
* registers that are not general-purpose (x87, SSE, segment, control, ...)
  are decoded as ``kind == "other"`` and must be rejected by the lifter.

Immediate convention: ``Operand.imm`` is the immediate value *after* the
architectural sign-/zero-extension to the operand size, represented as an
unsigned integer masked to ``size`` bytes. For example ``add rsi, -2`` has
``imm == 0xfffffffffffffffe`` and ``mov r8d, 0xffffffff`` has
``imm == 0xffffffff``. ``Operand.imm_signed`` gives the two's-complement view.
"""
from __future__ import annotations

from dataclasses import dataclass, field

try:  # pragma: no cover - exercised implicitly by every test that decodes
    import capstone
    from capstone import x86_const as _x86
except ImportError:  # pragma: no cover
    capstone = None
    _x86 = None


class DecoderUnavailable(RuntimeError):
    pass


class DecodeError(ValueError):
    pass


# --------------------------------------------------------------------------
# General-purpose register model
# --------------------------------------------------------------------------
GPR64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
_GPR32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi") + tuple(f"r{i}d" for i in range(8, 16))
_GPR16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di") + tuple(f"r{i}w" for i in range(8, 16))
_GPR8 = ("al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil") + tuple(f"r{i}b" for i in range(8, 16))
_GPR8H = {"ah": 0, "ch": 1, "dh": 2, "bh": 3}

_REG_TABLE = {}
for _i, _n in enumerate(GPR64):
    _REG_TABLE[_n] = (_i, 64, False)
for _i, _n in enumerate(_GPR32):
    _REG_TABLE[_n] = (_i, 32, False)
for _i, _n in enumerate(_GPR16):
    _REG_TABLE[_n] = (_i, 16, False)
for _i, _n in enumerate(_GPR8):
    _REG_TABLE[_n] = (_i, 8, False)
for _n, _i in _GPR8H.items():
    _REG_TABLE[_n] = (_i, 8, True)


@dataclass(frozen=True)
class Register:
    """A register reference.

    ``kind`` is ``"gpr"`` (general purpose, ``index`` 0..15 in hardware
    encoding order), ``"xmm"`` (``index`` 0..15), ``"rip"`` or ``"other"``. ``width`` is in bits.
    ``high8`` marks AH/CH/DH/BH (bits 8..15 of the 64-bit register).
    """
    name: str
    kind: str
    index: int | None
    width: int
    high8: bool = False

    @property
    def full(self) -> str | None:
        return GPR64[self.index] if self.kind == "gpr" else None

    def to_dict(self):
        return {"name": self.name, "kind": self.kind, "index": self.index,
                "width": self.width, "high8": self.high8}


def make_register(name: str) -> Register:
    name = name.lower()
    if name in _REG_TABLE:
        idx, width, high = _REG_TABLE[name]
        return Register(name, "gpr", idx, width, high)
    if name == "rip":
        return Register(name, "rip", None, 64)
    if name.startswith("xmm") and name[3:].isdigit() and int(name[3:]) < 16:
        return Register(name, "xmm", int(name[3:]), 128)
    return Register(name, "other", None, 0)


@dataclass(frozen=True)
class MemRef:
    segment: Register | None
    base: Register | None
    index: Register | None
    scale: int
    disp: int                 # signed displacement as encoded
    rip_target: int | None    # absolute VA when base is RIP

    def to_dict(self):
        return {
            "segment": self.segment.name if self.segment else None,
            "base": self.base.name if self.base else None,
            "index": self.index.name if self.index else None,
            "scale": self.scale,
            "disp": self.disp,
            "rip_target": self.rip_target,
        }


@dataclass(frozen=True)
class Operand:
    kind: str                       # "reg" | "imm" | "mem"
    size: int                       # bytes
    reg: Register | None = None
    imm: int | None = None          # unsigned, masked to size
    mem: MemRef | None = None
    access: str = ""                # "r", "w", "rw" or "" if unknown

    @property
    def bits(self) -> int:
        return self.size * 8

    @property
    def imm_signed(self) -> int | None:
        if self.imm is None:
            return None
        sign = 1 << (self.bits - 1)
        return self.imm - (1 << self.bits) if self.imm & sign else self.imm

    def to_dict(self):
        d = {"kind": self.kind, "size": self.size, "access": self.access}
        if self.reg is not None:
            d["reg"] = self.reg.to_dict()
        if self.imm is not None:
            d["imm"] = self.imm
        if self.mem is not None:
            d["mem"] = self.mem.to_dict()
        return d


# Control-flow classification ------------------------------------------------
FLOW_NONE = "none"
FLOW_JUMP = "jump"             # unconditional jmp
FLOW_COND = "cond_branch"      # jcc
FLOW_CALL = "call"
FLOW_RET = "ret"
FLOW_TRAP = "trap"             # int3, ud2, hlt ...


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int
    encoding: bytes
    mnemonic: str
    op_str: str
    operands: tuple[Operand, ...]
    prefixes: tuple[int, ...]
    flow: str
    direct_target: int | None      # for relative jmp/jcc/call
    is_indirect: bool              # jmp/call through reg or memory
    regs_read: tuple[str, ...] = field(default=())
    regs_written: tuple[str, ...] = field(default=())
    flags_tested: tuple[str, ...] = field(default=())
    flags_modified: tuple[str, ...] = field(default=())
    flags_undefined: tuple[str, ...] = field(default=())

    @property
    def next(self) -> int:
        return self.address + self.size

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()

    def to_dict(self):
        return {
            "address": self.address,
            "size": self.size,
            "bytes": self.encoding.hex(),
            "mnemonic": self.mnemonic,
            "op_str": self.op_str,
            "operands": [o.to_dict() for o in self.operands],
            "prefixes": list(self.prefixes),
            "flow": self.flow,
            "direct_target": self.direct_target,
            "is_indirect": self.is_indirect,
            "next_address": self.next,
            "regs_read": list(self.regs_read),
            "regs_written": list(self.regs_written),
            "flags_tested": list(self.flags_tested),
            "flags_modified": list(self.flags_modified),
            "flags_undefined": list(self.flags_undefined),
        }


# --------------------------------------------------------------------------
# Capstone glue
# --------------------------------------------------------------------------
_CS = None
_FLAG_NAMES = ("CF", "PF", "AF", "ZF", "SF", "OF", "DF", "TF", "IF")


def _cs():
    global _CS
    if capstone is None:
        raise DecoderUnavailable(
            "Capstone Python bindings are not installed; install capstone==5.0.3 "
            "(see docs/BASELINE_2026-10-25.md)")
    if _CS is None:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        md.syntax = capstone.CS_OPT_SYNTAX_INTEL
        _CS = md
    return _CS


def _flag_bits(prefix):
    out = {}
    for name in _FLAG_NAMES:
        const = getattr(_x86, f"X86_EFLAGS_{prefix}_{name}", None)
        if const is not None:
            out[name] = const
    return out


def _flags(mask, prefix):
    return tuple(n for n, bit in _flag_bits(prefix).items() if mask & bit)


def _mask(value, size):
    return value & ((1 << (8 * size)) - 1)


def _access(op):
    acc = getattr(op, "access", 0)
    s = ""
    if acc & capstone.CS_AC_READ:
        s += "r"
    if acc & capstone.CS_AC_WRITE:
        s += "w"
    return s


def _convert(md, insn):
    ops = []
    for op in insn.operands:
        acc = _access(op)
        if op.type == _x86.X86_OP_REG:
            ops.append(Operand("reg", op.size, reg=make_register(md.reg_name(op.reg)), access=acc))
        elif op.type == _x86.X86_OP_IMM:
            ops.append(Operand("imm", op.size, imm=_mask(op.imm, op.size), access=acc))
        elif op.type == _x86.X86_OP_MEM:
            m = op.mem
            seg = make_register(md.reg_name(m.segment)) if m.segment else None
            base = make_register(md.reg_name(m.base)) if m.base else None
            index = make_register(md.reg_name(m.index)) if m.index else None
            rip_target = None
            if base is not None and base.kind == "rip":
                if index is not None:
                    raise DecodeError(f"0x{insn.address:x}: RIP-relative with index is invalid")
                rip_target = _mask(insn.address + insn.size + m.disp, 8)
            ops.append(Operand("mem", op.size, mem=MemRef(seg, base, index, m.scale, m.disp, rip_target),
                               access=acc))
        else:  # pragma: no cover - x86 has no other operand kinds in Capstone 5
            raise DecodeError(f"0x{insn.address:x}: unknown operand type {op.type}")

    groups = set(insn.groups)
    flow, target, indirect = FLOW_NONE, None, False
    is_jump = capstone.CS_GRP_JUMP in groups
    if capstone.CS_GRP_CALL in groups:
        flow = FLOW_CALL
    elif capstone.CS_GRP_RET in groups:
        flow = FLOW_RET
    elif is_jump:
        flow = FLOW_JUMP if insn.id == _x86.X86_INS_JMP else FLOW_COND
    elif insn.id in (_x86.X86_INS_UD2, _x86.X86_INS_HLT, _x86.X86_INS_INT3, _x86.X86_INS_INT):
        flow = FLOW_TRAP
    if flow in (FLOW_CALL, FLOW_JUMP, FLOW_COND):
        if capstone.CS_GRP_BRANCH_RELATIVE in groups and ops and ops[0].kind == "imm":
            target = ops[0].imm
        else:
            indirect = True

    try:
        rr, rw = insn.regs_access()
        regs_read = tuple(md.reg_name(r) for r in rr)
        regs_written = tuple(md.reg_name(r) for r in rw)
    except capstone.CsError:  # pragma: no cover
        regs_read = regs_written = ()

    eflags = insn.eflags
    tested = _flags(eflags, "TEST")
    modified = tuple(sorted(set(_flags(eflags, "MODIFY")) | set(_flags(eflags, "RESET"))
                            | set(_flags(eflags, "SET")), key=_FLAG_NAMES.index))
    undefined = _flags(eflags, "UNDEFINED")

    return Instruction(
        address=insn.address, size=insn.size, encoding=bytes(insn.bytes),
        mnemonic=insn.mnemonic, op_str=insn.op_str, operands=tuple(ops),
        prefixes=tuple(p for p in insn.prefix if p),
        flow=flow, direct_target=target, is_indirect=indirect,
        regs_read=regs_read, regs_written=regs_written,
        flags_tested=tested, flags_modified=modified, flags_undefined=undefined,
    )


def decode_one(code: bytes, address: int) -> Instruction:
    """Decode exactly one instruction at the start of ``code``."""
    md = _cs()
    for insn in md.disasm(bytes(code), address, 1):
        return _convert(md, insn)
    raise DecodeError(f"0x{address:x}: undecodable bytes {bytes(code[:15]).hex()}")


def decode_linear(code: bytes, address: int) -> list[Instruction]:
    """Linear-sweep decode of a whole buffer; raises on any undecodable byte."""
    out, off = [], 0
    while off < len(code):
        insn = decode_one(code[off:off + 15], address + off)
        out.append(insn)
        off += insn.size
    return out
