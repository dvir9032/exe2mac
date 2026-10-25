# Independent model of test/io.c for the reference invocation
#   io.exe alpha "b c" q\"uote "back\slash\\" ""   < test/golden/io.input
# (argv after the program name: alpha | b c | q"uote | back\slash\ | <empty>)
import os, sys
ARGS = ["alpha", "b c", 'q"uote', "back\\slash\\", ""]
data = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "io.input"), "rb").read()
out = "args:" + "".join(f" [{a}]" for a in ARGS) + "\n"
lines = data.count(b"\n")
words, inword, h = 0, False, 0
for c in data:
    h = (h * 31 + c) & ((1 << 64) - 1)
    if c in b" \n\t\r":
        inword = False
    elif not inword:
        inword, words = True, words + 1
out += f"stdin: bytes={len(data)} lines={lines} words={words} hash={h & 0xffffffff}\n"
first = data.split(b"\n", 1)[0]
out += "reversed first line: " + first[::-1].decode() + "\n"
out += "heap: zeroed=1 aligned16=1 distinct=1 free=1\n"
out += "virtual: ok=1 aligned64k=1 zeroed=1 last=90 release=1\n"
# SetLastError/GetLastError round trip; WriteFile on a bogus handle fails with
# ERROR_INVALID_HANDLE (6) and zeroes *lpNumberOfBytesWritten first.
out += "lasterror: set=1234 badwrite=0 err=6 written=0\n"
sys.stdout.buffer.write(out.encode())
sys.stderr.write(f"exit={len(ARGS)}\n")
