# Independent model of test/tail.c.
import sys
M = (1 << 64) - 1
depth = 1000001
is_even = lambda n: 1 if n % 2 == 0 else 0          # even/odd by mutual recursion
is_odd = lambda n: 1 - is_even(n)
def machine(n, acc):
    state = 0                                        # 0 = st_a, 1 = st_b
    while n:
        if state == 0:
            state, acc = n & 1, (acc * 3 + 1) & M
        else:
            state, acc = (n >> 1) & 1, acc ^ (acc >> 7)
        n -= 1
    return acc
out = (f"parity: {is_even(depth)} {is_odd(depth)}\n"
       f"lasterror: 4242\n"
       f"apply: {12 * 12 + 1}\n"
       f"machine: {machine(depth, 7)}\n")
sys.stdout.buffer.write(out.encode())
sys.stderr.write(f"exit={is_odd(depth) * 10 + 3}\n")
