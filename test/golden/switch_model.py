# Independent model of test/switch.c (Windows x64; long long = int64).
import sys
M = (1 << 64) - 1
def s64(v):
    v &= M
    return v - (1 << 64) if v >> 63 else v
def tdiv(a, b):
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q
def op(code, a, b):
    if code == 0: return s64(a + b)
    if code == 1: return s64(a - b)
    if code == 2: return s64(a * b)
    if code == 3: return tdiv(a, b) if b else 0
    if code == 4: return a - tdiv(a, b) * b if b else 0
    if code == 5: return s64(a & b)
    if code == 6: return s64(a | b)
    if code == 7: return s64(a ^ b)
    if code == 8: return s64(a << (b & 63))   # compiled to SHL (two's-complement wrap)
    if code == 9: return a >> (b & 63)        # compiled to SAR
    if code == 10: return s64(-a)
    if code == 11: return s64(~a)
    return 999
salt = 3
acc = 0
line = "op:"
for c in range(-1, 13):
    r = op(c, 1000 + salt, -7 + salt)
    line += " " + str(r); acc += r
out = [line]
days = {0: ("<", "sun"), 1: ("<", "mon"), 2: ("[", "tue"), 3: ("[", "wed"),
        4: ("{", "thu"), 5: ("{", "fri"), 6: ("(", "sat")}
line = "day:"
for d in range(9):
    pre, name = days.get(d, ("", "???"))
    line += " " + pre + name
out.append(line)
sp = {7: 1, 1000: 2, -50: 3, 123456: 4}
line = "sparse:"
for x in (7, 1000, -50, 123456, 8, 0):
    line += " " + str(sp.get(x, 0)); acc += sp.get(x, 0)
out.append(line)
sys.stdout.buffer.write(("\n".join(out) + "\n").encode())
sys.stderr.write(f"exit={acc & 0x7f}\n")
