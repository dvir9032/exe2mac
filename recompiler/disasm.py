"""x86-64 decoding front-end.

Uses objdump (binutils or llvm) in Intel syntax as the instruction decoder and
turns its output into structured Instruction objects. The decoder is isolated
here so it can be swapped for capstone / iced-x86 later without touching the
translator.
"""
import os
import re
import shutil
import subprocess


class Instruction:
    __slots__ = ("addr", "size", "mnem", "ops", "text", "encoding")

    def __init__(self, addr, size, mnem, ops, text, encoding=b""):
        self.addr, self.size, self.mnem, self.ops, self.text = addr, size, mnem, ops, text
        self.encoding = bytes(encoding)

    @property
    def next(self):
        return self.addr + self.size

    def to_dict(self):
        return {
            "address": self.addr,
            "size": self.size,
            "bytes": self.encoding.hex(),
            "mnemonic": self.mnem,
            "operands": list(self.ops),
            "text": self.text,
        }

    def __repr__(self):
        return f"0x{self.addr:x}: {self.text}"


LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(.*))?$")
PREFIXES = {"rex", "rex.W", "data16", "cs", "ds", "es", "ss", "fs", "gs", "addr32", "notrack", "bnd", "lock", "rep", "repz", "repe", "repnz", "repne"}


def split_operands(s):
    ops, depth, cur = [], 0, ""
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            ops.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return ops


_GNU_OBJDUMP_CANDIDATES = ("objdump", "gobjdump", "x86_64-w64-mingw32-objdump",
                           "/opt/homebrew/opt/binutils/bin/objdump", "/usr/local/opt/binutils/bin/objdump")


def find_gnu_objdump():
    """Return a GNU objdump path, or None.

    This text parser expects GNU binutils output. On macOS, `objdump` is
    llvm-objdump, whose output format differs, so it is not accepted
    (install GNU binutils, e.g. `brew install binutils`). Override with
    EXE2MAC_OBJDUMP=/path/to/gnu/objdump.
    """
    env = os.environ.get("EXE2MAC_OBJDUMP")
    for cand in ((env,) if env else ()) + _GNU_OBJDUMP_CANDIDATES:
        path = shutil.which(cand) or (cand if os.path.isabs(cand) and os.access(cand, os.X_OK) else None)
        if not path:
            continue
        try:
            ver = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10).stdout
        except OSError:
            continue
        if "GNU objdump" in ver:
            return path
    return None


def disassemble(exe_path, start, end):
    objdump = find_gnu_objdump()
    if not objdump:
        raise RuntimeError("GNU objdump not found (llvm-objdump output is not supported by this parser; "
                           "install GNU binutils or set EXE2MAC_OBJDUMP)")
    out = subprocess.run(
        [objdump, "-d", "-M", "intel", "-w", "--start-address", hex(start),
         "--stop-address", hex(end), exe_path],
        check=True, capture_output=True, text=True).stdout
    insns = []
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        byte_tokens = m.group(2).split()
        encoding = bytes(int(token, 16) for token in byte_tokens)
        nbytes = len(byte_tokens)
        text = (m.group(3) or "").split("#")[0].strip()
        text = re.sub(r"<[^>]*>", "", text).strip()
        if insns and insns[-1].addr + insns[-1].size == addr and not text:
            insns[-1].size += nbytes  # continuation line of a long instruction
            insns[-1].encoding += encoding
            continue
        words = text.split(None, 1)
        # strip prefixes like "data16 cs nop ..." / "rep stos ..."
        prefixes = []
        while words and words[0] in PREFIXES:
            prefixes.append(words[0])
            rest = words[1] if len(words) > 1 else ""
            words = rest.split(None, 1)
        mnem = words[0] if words else "(bad)"
        if prefixes and prefixes[-1].startswith("rep") and mnem in ("stos", "movs", "lods", "cmps", "scas"):
            mnem = prefixes[-1] + " " + mnem
        ops = split_operands(words[1]) if len(words) > 1 else []
        insns.append(Instruction(addr, nbytes, mnem, ops, text, encoding))
    return insns
