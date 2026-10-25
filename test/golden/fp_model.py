# Independent model of test/fp.c as executed by x86-64 SSE with the default
# MXCSR (round-to-nearest, no FTZ/DAZ, exceptions masked). NaN rules per
# Intel SDM Vol. 1 Table 4-7: first NaN operand wins (quieted); an invalid
# operation yields the QNaN indefinite 0xFFF8000000000000 (sign set).
import math, struct, sys

def bits(x): return struct.unpack("<Q", struct.pack("<d", x))[0]
def flt(b): return struct.unpack("<d", struct.pack("<Q", b))[0]
def isnan_b(b): return (b >> 52) & 0x7FF == 0x7FF and b & ((1 << 52) - 1)
IND, QB = 0xFFF8000000000000, 1 << 51

def f32bits(x):
    try:
        return struct.unpack("<I", struct.pack("<f", x))[0]
    except OverflowError:                       # finite double that rounds to +-inf
        return 0xFF800000 if x < 0 else 0x7F800000
def f32(b): return struct.unpack("<f", struct.pack("<I", b))[0]
def isnan32(b): return (b >> 23) & 0xFF == 0xFF and b & 0x7FFFFF
IND32, QB32 = 0xFFC00000, 1 << 22

def arith(op, a, b):
    if isnan_b(a): return a | QB
    if isnan_b(b): return b | QB
    x, y = flt(a), flt(b)
    if op == "/":
        if y == 0:
            if x == 0: return IND
            neg = (math.copysign(1, x) < 0) != (math.copysign(1, y) < 0)
            return bits(-math.inf if neg else math.inf)
        r = x / y
    elif op == "+": r = x + y
    elif op == "-": r = x - y
    else: r = x * y
    return IND if math.isnan(r) else bits(r)

def arith32(op, a, b):
    if isnan32(a): return a | QB32
    if isnan32(b): return b | QB32
    x, y = f32(a), f32(b)
    if op == "/" and y == 0:
        if x == 0: return IND32
        neg = (math.copysign(1, x) < 0) != (math.copysign(1, y) < 0)
        return 0xFF800000 if neg else 0x7F800000
    r = {"+": x + y, "-": x - y, "*": x * y}.get(op) if op != "/" else x / y
    if math.isnan(r): return IND32
    return f32bits(r)              # double rounding through binary64 is exact for + - * /

def sqrt(b):
    if isnan_b(b): return b | QB
    x = flt(b)
    if x < 0: return IND
    return bits(math.sqrt(x))      # sqrt(-0.0) == -0.0

def dmin(a, b): return a if flt(a) < flt(b) else b    # minsd semantics == C `a < b ? a : b`
def dmax(a, b): return a if flt(a) > flt(b) else b

dv = [bits(v) for v in (1.5, -2.25, 0.1, 1e308, 4.9406564584124654e-324, -0.0, math.inf, 3.0)]
fv = [f32bits(v) for v in (1.5, -0.1, 3.4e38, 1e-45)]
iv = [0, -1, 9007199254740993, 9223372036854775807]
N = 8
hx = lambda b: " %016x" % b
hx32 = lambda b: " %08x" % b
out = []
for name, op in (("add", "+"), ("sub", "-"), ("mul", "*"), ("div", "/")):
    out.append(name + ":" + "".join(hx(arith(op, dv[i], dv[i + 1])) for i in range(N - 1)))
out.append("sqrt:" + "".join(hx(sqrt(dv[i])) for i in range(N)))
z, inf = dv[5], dv[6]
nan = arith("/", z, z)
out.append("nan:" + hx(nan) + hx(arith("-", inf, inf)) + hx(sqrt(dv[1]))
           + hx(arith("+", nan, bits(1.0))) + hx(arith("+", bits(1.0), arith("-", inf, inf))))
line = "minmax:"
for i in range(N - 1):
    line += hx(dmin(dv[i], dv[i + 1])) + hx(dmax(dv[i], dv[i + 1]))
line += hx(dmin(nan, bits(1.0))) + hx(dmax(bits(1.0), nan)) + hx(dmin(bits(0.0), bits(-0.0))) + hx(dmax(bits(-0.0), bits(0.0)))
out.append(line)
out.append("absneg:" + "".join(hx(b & ~(1 << 63)) + hx(b ^ (1 << 63)) for b in dv))
score = 0
line = "cmp:"
for i in range(N - 1):
    a, b = flt(dv[i]), flt(dv[i + 1])
    c = (a < b) + 2 * (a == b) + 4 * (a > b) + 8 * (a != a)
    line += " %d" % c; score += c
n = flt(nan)
c = (n < 1.0) + 2 * (n == n) + 4 * (n > 1.0) + 8 * (n != n)
line += " %d" % c; score += c
out.append(line)
line = "d2i:"
for b in dv:
    x = flt(b)
    if -1e18 < x < 1e18:
        line += " %d/%d" % (math.trunc(x), math.trunc(x * 1000.0))
out.append(line)
out.append("i2d:" + "".join(hx(bits(float(v))) for v in iv) + hx(bits(float(-1))))
line = "float:"
for i in range(3):
    line += hx32(arith32("+", fv[i], fv[i + 1])) + hx32(arith32("*", fv[i], fv[i + 1])) + hx32(arith32("/", fv[i], fv[i + 1]))
out.append(line)
line = "f2d:" + "".join(hx(bits(f32(b))) for b in fv)
line += "".join(hx32(f32bits(flt(dv[i]))) for i in range(5))
out.append(line)
sys.stdout.buffer.write(("\n".join(out) + "\n").encode())
sys.stderr.write("exit=%d\n" % score)
