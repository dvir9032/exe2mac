# Independent model of test/vec.c (C semantics on Windows x64; no UB in the
# source). Doubles are Python floats; float (binary32) results are rounded
# after every operation, as SSE does (no FMA on baseline x86-64).
import struct, sys
M64, M32 = (1 << 64) - 1, (1 << 32) - 1
def s(v, bits): v &= (1 << bits) - 1; return v - (1 << bits) if v >> (bits - 1) else v
def f32(x): return struct.unpack("<f", struct.pack("<f", x))[0]
def dbits(x): return struct.unpack("<Q", struct.pack("<d", x))[0]
def fbits(x): return struct.unpack("<I", struct.pack("<f", x))[0]
N = 203
seed = 0x9e3779b97f4a7c15
def rnd():
    global seed
    seed ^= (seed << 13) & M64; seed ^= seed >> 7; seed ^= (seed << 17) & M64
    return seed
b8, s16, i32, j32, u32, dv, ev, fv = ([0] * N for _ in range(8))
for i in range(N):
    r = rnd()
    b8[i] = r & 0xff
    s16[i] = s(r >> 8, 16)
    i32[i] = ((r >> 16) & 0x3fffffff) - 0x20000000
    j32[i] = (r >> 40) - 0x800000
    u32[i] = (r >> 24) & M32
    dv[i] = float(s(r >> 32, 32)) / 1024.0
    ev[i] = (i - 100) * 0.5
    fv[i] = f32(float(i % 17) - 8.0)
ph = lambda v: " %016x" % (v & M64)
out = []
out.append("bytes:" + ph(sum(b8)) + ph(sum(1 for x in b8 if x == b8[7])))
sum_u = lambda a: sum(a) & M32
prod = sum(a * b for a, b in zip(i32, j32))
out.append("i32:" + ph(sum_u(i32)) + ph(prod) + ph(max(i32) & M32) + ph(min(u32)))
j32 = [a + b * 3 - (a >> 2) for a, b in zip(i32, j32)]          # >> on negative ints floors, like SAR
out.append("add:" + ph(j32[0] & M32) + ph(j32[N // 2] & M32) + ph(j32[N - 1] & M32) + ph(sum_u(j32)))
i64 = [x * 8 for x in s16]
out.append("widen:" + ph(i64[0]) + ph(i64[N - 1]))
up = [32 + x % 95 for x in b8]
up = [c - 32 if ord("a") <= c <= ord("z") else c for c in up]
out.append("upper: " + bytes(up[:40]).decode())
h = 0
for i, a in enumerate(u32):
    h ^= ((a << (i & 7)) & M64) ^ (a >> 3)
out.append("xor:" + ph(h))
def dot(a, b):
    acc = 0.0
    for x, y in zip(a, b): acc += x * y
    return acc
out.append("dot:" + ph(dbits(dot(dv, ev))))
dv = [y + 0.25 * x for y, x in zip(dv, ev)]
out.append("axpy:" + ph(dbits(dot(dv, dv))))
fv = [f32(f32(x * 1.5) + 1.0) for x in fv]
fs = 0.0
for x in fv: fs = f32(fs + x)
out.append("float:" + ph(fbits(fs)))
sys.stdout.buffer.write(("\n".join(out) + "\n").encode())
sys.stderr.write("exit=42\n")
