# Independent model of test/ops.c semantics (C99 on LLP64 Windows x64).
M64 = (1 << 64) - 1
def tdiv(a, b):  # C truncating division
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q
out = []
check = 0
vs8 = [-128, -1, 0, 127]; vu8 = [0, 1, 200, 255]
vs16 = [-32768, -2, 30000]; vu16 = [0, 40000, 65535]
counts = [0, 1, 7, 31, 33]
sdiv = [(100, 7), (-100, 7), (100, -7), (-9223372036854775807, 3)]
udiv = [(1000000007, 10), (M64, 3), (12345, 12346)]
hx = lambda v: "0x%016x" % (v & M64)
out.append("s8: " + " ".join(str(v) for v in vs8)); check = (check + sum(v & M64 for v in vs8)) & M64
out.append("u8: " + " ".join(str(v) for v in vu8)); check = (check + sum(vu8)) & M64
out.append("s16: " + " ".join(str(v) for v in vs16)); check = (check + sum(v & M64 for v in vs16)) & M64
out.append("u16: " + " ".join(str(v) for v in vu16)); check = (check + sum(vu16)) & M64
out.append("shl: " + " ".join(hx(0x8000000000000001 << (c & 63)) for c in counts))
out.append("sar: " + " ".join(str((-1000000000000) >> (c & 63)) for c in counts))
out.append("shr32: " + " ".join(str(0xdeadbeef >> (c & 31)) for c in counts))
out.append("sdiv: " + " ".join(f"{tdiv(a,b)}r{a - tdiv(a,b)*b}" for a, b in sdiv))
parts = []
for a, b in udiv:
    parts.append(f"{a//b}r{a%b}"); check ^= a // b
out.append("udiv: " + " ".join(parts))
cm = []
for a, b in zip(vs8, vu8):
    cm.append(str(int(a < b) + 2 * int(a == b) + 4 * int((a & 0xffffffff) > (b & 0xffffffff))))
out.append("cmp: " + " ".join(cm))
x = (udiv[1][0] << 64) | udiv[0][0]; y = (udiv[2][0] << 64) | udiv[1][0]
M128 = (1 << 128) - 1
s_ = (x + y) & M128; d_ = (x - y) & M128
out.append("u128: " + " ".join(hx(v) for v in (s_ >> 64, s_, d_ >> 64, d_)))
out.append("not: " + hx(~udiv[0][0]))
table = {0: 11, 1: 22, 2: 33, 3: 44, 4: 55, 5: 66}
out.append("switch: " + " ".join(str(table.get(i, -1)) for i in range(-1, 8)))
out.append("xchg: " + hx(0x1111) + " " + hx(0x2222))
a = list(b"x" * 16); a[4:12] = b"abcdefgh"
out.append("rep: " + bytes(a).decode())
import sys
# label() prints "name: " and every item is preceded by print(" ") -> two spaces after the colon
out = [l.split(": ", 1)[0] + ":  " + l.split(": ", 1)[1] for l in out]
sys.stdout.buffer.write(("\n".join(out) + "\n").encode())
sys.stderr.write(f"exit={check & 0xff}\n")
