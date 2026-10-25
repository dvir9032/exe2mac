"""Translation entry points: PE32+ x86-64 -> generated C -> native executable.

The generated C is portable; the native code for the host (macOS ARM64 on a
Mac) is produced by the host C compiler. No guest instruction is interpreted
or emulated at run time.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from .cfg import CFGError
from .decoder import DecodeError
from .disasm import disassemble
from .lift_c import TranslationError as _LiftError, lift_program
from .pe import PE

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_SOURCES = ["loader.c", "dispatch.c", "winapi_bridge.c", "winapi_shims.c", "process.c", "guest_heap.c",
                   "guest_mem.c", "fault.c", "main.c"]

# Instructions observed in the supplied hello.exe (linear sweep). Kept for
# reference; the real work list is the reachable set computed by cfg.discover.
FIXTURE_MNEMONICS = frozenset({
    "add", "call", "cdq", "cmovs", "cmp", "dec", "idiv", "imul", "inc",
    "ja", "jae", "jb", "je", "jg", "jle", "jmp", "jne", "jns", "lea",
    "mov", "movabs", "movsxd", "mul", "neg", "nop", "or", "pop", "push",
    "ret", "shr", "sub", "test", "xchg", "xor",
})


class TranslationError(RuntimeError):
    pass


def inventory(exe_path, start, end):
    """Return decoded instruction count and per-mnemonic counts (objdump, linear)."""
    insns = disassemble(exe_path, start, end)
    return len(insns), Counter(i.mnem for i in insns)


def translate(exe_path, strict_indirect_jumps: bool = False, trap_unsupported: bool = False) -> str:
    """Return the generated C translation unit for ``exe_path`` or raise TranslationError."""
    try:
        return lift_program(PE(exe_path), strict_indirect_jumps=strict_indirect_jumps,
                            trap_unsupported=trap_unsupported)
    except (_LiftError, CFGError, DecodeError) as exc:
        raise TranslationError(str(exc)) from exc


def default_cc() -> str:
    cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not cc:
        raise TranslationError("no C compiler found (set CC)")
    return cc


def compile_c(c_path, out_path, cc=None, extra_flags=(), opt="-O2"):
    """Compile generated C plus the runtime into a native executable."""
    cc = cc or default_cc()
    # -ffp-contract=off: never fuse guest MUL+ADD into a host FMA (different rounding).
    flags = ["-std=c11", "-D_DEFAULT_SOURCE", opt, "-Wall", "-Wextra", "-ffp-contract=off",
             "-I", str(ROOT), "-I", str(ROOT / "runtime")]
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        flags += ["-arch", "arm64"]
    cmd = [cc, *flags, *extra_flags, str(c_path),
           *[str(ROOT / "runtime" / s) for s in RUNTIME_SOURCES], "-lm", "-o", str(out_path)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise TranslationError("C compilation failed:\n" + " ".join(cmd) + "\n" + r.stderr)
    return cmd


def build(exe_path, out_path, cc=None, extra_flags=(), keep_c=True, strict_indirect_jumps=False,
          trap_unsupported=False):
    """Translate ``exe_path`` and build a native executable at ``out_path``."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    c_path = out_path.with_suffix(".gen.c") if keep_c else out_path.parent / (out_path.name + ".tmp.c")
    c_path.write_text(translate(exe_path, strict_indirect_jumps=strict_indirect_jumps,
                                trap_unsupported=trap_unsupported))
    try:
        compile_c(c_path, out_path, cc, extra_flags)
    finally:
        if not keep_c and c_path.exists():
            c_path.unlink()
    return out_path
