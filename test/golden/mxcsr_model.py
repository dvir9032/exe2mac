# Independent model of test/mxcsr.c: exact rational arithmetic (fractions),
# rounded to binary64 per the MXCSR rounding mode, with x86 flag rules
# (tininess after rounding; FTZ flushes tiny results and sets UE|PE; DAZ
# turns denormal inputs into zero without DE).
import struct, sys
from fractions import Fraction as Fr
IE, DE, ZE, OE, UE, PE = 1, 2, 4, 8, 16, 32
RN, RD, RU, RZ = 0, 1, 2, 3
SIGN = 1 << 63

def val(b):
    e, f, s = (b >> 52) & 0x7FF, b & ((1 << 52) - 1), -1 if b >> 63 else 1
    if e == 0: return s * Fr(f, 1 << 1074)
    return s * (Fr((1 << 52) | f) * Fr(2) ** (e - 1075))
def is_den(b): return (b >> 52) & 0x7FF == 0 and b & ((1 << 52) - 1)

def floor_log2(a):
    n, d = a.numerator, a.denominator
    e = n.bit_length() - d.bit_length()
    if Fr(2) ** e > a: e -= 1
    return e

def round64(x, mode, ftz=False):
    """x: nonzero Fraction -> (bits, flags)"""
    neg = x < 0; a = -x if neg else x
    def step(lsb):
        y = a / Fr(2) ** lsb
        q = y.numerator // y.denominator; r = y - q
        inexact = r != 0
        if mode == RN: up = r > Fr(1, 2) or (r == Fr(1, 2) and q % 2 == 1)
        elif mode == RZ: up = False
        elif mode == RU: up = inexact and not neg
        else: up = inexact and neg
        return (q + up) * Fr(2) ** lsb, inexact
    E = floor_log2(a)
    v, inexact = step(max(E, -1022) - 52)
    tiny = step(E - 52)[0] < Fr(2) ** -1022          # tininess after rounding (unbounded exponent)
    if tiny and ftz:
        return (SIGN if neg else 0), UE | PE
    flags = (PE if inexact else 0) | (UE if tiny and inexact else 0)
    if v >= Fr(2) ** 1024:
        flags |= OE | PE
        big = {RN: True, RZ: False, RU: not neg, RD: neg}[mode]
        return (SIGN if neg else 0) | (0x7FF0000000000000 if big else 0x7FEFFFFFFFFFFFFF), flags
    if v < Fr(2) ** -1022:
        bits = int(v * Fr(2) ** 1074)
    else:
        e = floor_log2(v)
        bits = ((e + 1023) << 52) | (int(v / Fr(2) ** (e - 52)) - (1 << 52))
    return (SIGN if neg else 0) | bits, flags

def op(kind, a, b, mode=RN, ftz=False, daz=False):
    fl = 0
    if daz:
        a = (a & SIGN) if is_den(a) else a
        b = (b & SIGN) if is_den(b) else b
    elif is_den(a) or is_den(b):
        fl |= DE
    x, y = val(a), val(b)
    if kind == "add": r = x + y
    elif kind == "mul": r = x * y
    else: r = x / y
    if r == 0:
        if kind == "add" and (a >> 63) != (b >> 63):
            return (SIGN if mode == RD else 0), fl
        return (SIGN if (a >> 63) ^ (b >> 63) and kind != "add" else (a & SIGN if kind == "add" else 0)), fl
    bits, f2 = round64(r, mode, ftz)
    return bits, fl | f2

def cvt(a, mode):
    x = val(a); neg = x < 0; m = -x if neg else x
    q = m.numerator // m.denominator; r = m - q
    inexact = r != 0
    if mode == RN: up = r > Fr(1, 2) or (r == Fr(1, 2) and q % 2 == 1)
    elif mode == RZ: up = False
    elif mode == RU: up = inexact and not neg
    else: up = inexact and neg
    q += up
    return ((-q) & ((1 << 64) - 1) if neg else q), (PE if inexact else 0)

ONE, THREE, TEN = 0x3FF0000000000000, 0x4008000000000000, 0x4024000000000000
out = []
def show(label, res):
    bits, fl = res
    out.append(f"{label} {bits:016x} {fl:02x}")
for m, name in enumerate(("rn", "rd", "ru", "rz")):
    out.append(f"{name}:")
    show("  1/3  ", op("div", ONE, THREE, m))
    show("  1/10 ", op("div", ONE, TEN, m))
    show(" -1/10 ", op("div", ONE | SIGN, TEN, m))
    show("  1-1  ", op("add", ONE, ONE | SIGN, m))
    show("  max*2", op("mul", 0x7FEFFFFFFFFFFFFF, 0x4000000000000000, m))
    show("  cvt 2.5 ", cvt(0x4004000000000000, m))
    show("  cvt-2.5 ", cvt(0xC004000000000000, m))
    show("  cvt 3.5 ", cvt(0x400C000000000000, m))
out.append("tiny:")
show("  rn      ", op("mul", 0x0010000000000000, 0x3FEFFFFFFFFFFFFF))
show("  rn ftz  ", op("mul", 0x0010000000000000, 0x3FEFFFFFFFFFFFFF, ftz=True))
show("  rz      ", op("mul", 0x0010000000000000, 0x3FEFFFFFFFFFFFFF, RZ))
show("  half    ", op("mul", 0x0010000000000000, 0x3FE0000000000000))
show("  half ftz", op("mul", 0x0010000000000000, 0x3FE0000000000000, ftz=True))
out.append("daz:")
show("  den+0   ", op("add", 1, 0))
show("  den+0 d ", op("add", 1, 0, daz=True))
show("  den*1   ", op("mul", 0x000FFFFFFFFFFFFF, ONE))
show("  den*1 d ", op("mul", 0x000FFFFFFFFFFFFF, ONE, daz=True))
out.append("invalid:")
# SDM: invalid operations return the QNaN indefinite (sign set) with IE;
# an SNaN operand is returned quieted with IE; x/0 gives inf with ZE.
show("  0/0     ", (0xFFF8000000000000, IE))
show("  sqrt-1  ", (0xFFF8000000000000, IE))
show("  snan+1  ", (0x7FF8000000000001, IE))
show("  1/0     ", (0x7FF0000000000000, ZE))
out.append("unmasking ZE and dividing by zero")
sys.stdout.buffer.write(("\n".join(out) + "\n").encode())
# Unmasked ZE -> #XM -> STATUS_FLOAT_MULTIPLE_FAULTS (0xC00002B4); POSIX keeps 0xB4.
sys.stderr.write("exit=180\n")
