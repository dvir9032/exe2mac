"""Gap report for a real PE32+ executable: how far is it from translatable?

Uses the exception directory (.pdata) to enumerate every function, decodes
each one linearly, and asks the lifter whether it can translate each
instruction in isolation. Also lists imports per DLL and PE features the
runtime does not implement. Read-only: the executable is never run.

    python3 scripts/gap_report.py path/to/program.exe [--json out.json]
"""
import argparse
import collections
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recompiler import decoder as dec                     # noqa: E402
from recompiler.cfg import Program                       # noqa: E402
from recompiler.lift_c import SUPPORTED_IMPORTS, Lifter, TranslationError  # noqa: E402
from recompiler.pe import PE                             # noqa: E402

DIRS = ["export", "import", "resource", "exception", "security", "basereloc", "debug", "arch",
        "globalptr", "tls", "loadconfig", "boundimport", "iat", "delayimport", "clr"]
CONTROL = {"call", "jmp", "ret", "retn"}


def pdata_functions(pe):
    rva, size = pe.dirs[3] if len(pe.dirs) > 3 else (0, 0)
    out = []
    for i in range(size // 12):
        b, e, _ = struct.unpack_from("<III", pe.image, rva + 12 * i)
        out.append((b, e))
    return out


def classify(lifter, insn):
    """None if the lifter accepts the instruction in isolation, else a reason key."""
    if insn.mnemonic in CONTROL or insn.mnemonic.startswith("j") or insn.mnemonic.startswith("loop"):
        return None                                       # control flow: handled by the CFG/lifter
    try:
        lifter.lift_insn(insn, insn.address, [insn.address + insn.size])
        return None
    except TranslationError as e:
        return f"{insn.mnemonic}: {str(e).split(':', 2)[-1].strip()[:60]}"
    except Exception as e:                                # noqa: BLE001 - report, never crash
        return f"{insn.mnemonic}: internal {type(e).__name__}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--json")
    a = ap.parse_args()
    pe = PE(a.exe)
    prog = Program(pe.image_base, pe.image_base + pe.entry_rva, {}, {}, [], [])
    lifter = Lifter(pe, prog)

    funcs = [[r] for r in pdata_functions(pe)]          # each function: list of (begin, end) RVA ranges
    if not funcs:                                         # no .pdata (e.g. -fno-asynchronous-unwind-tables):
        from recompiler.cfg import discover               # use the recursive-descent CFG's blocks instead
        p = discover(pe)
        funcs = [[(blk.start - pe.image_base, blk.end - pe.image_base) for blk in f.blocks.values()]
                 for f in p.functions.values()]
    total = ok_funcs = 0
    bad_insn = collections.Counter()
    bad_funcs_by_reason = collections.Counter()
    mnem = collections.Counter()
    undecodable = 0
    for ranges in funcs:
        insns = []
        try:
            for b, e in ranges:
                insns += dec.decode_linear(bytes(pe.image[b:e]), pe.image_base + b)
        except Exception:                                 # noqa: BLE001
            undecodable += 1
            continue
        reasons = set()
        for insn in insns:
            total += 1
            mnem[insn.mnemonic] += 1
            r = classify(lifter, insn)
            if r:
                bad_insn[r] += 1
                reasons.add(r.split(":")[0])
        if not reasons:
            ok_funcs += 1
        for r in reasons:
            bad_funcs_by_reason[r] += 1

    imports = collections.defaultdict(list)
    for _, dll, sym in pe.imports:
        imports[dll].append(sym)
    have = {f"{d}!{s}".lower() for d, s in SUPPORTED_IMPORTS} if isinstance(next(iter(SUPPORTED_IMPORTS)), tuple) \
        else {s.lower() for s in SUPPORTED_IMPORTS}

    def supported(dll, sym):
        return f"{dll}!{sym}".lower() in have or sym.lower() in have

    features = [n for n, (rva, sz) in zip(DIRS, pe.dirs) if sz and n not in ("import", "iat", "basereloc", "debug", "security")]
    rep = {
        "file": os.path.basename(a.exe),
        "subsystem": {2: "GUI", 3: "console"}.get(pe.subsystem, pe.subsystem),
        "functions": len(funcs), "functions_undecodable": undecodable,
        "functions_all_instructions_liftable": ok_funcs,
        "instructions": total,
        "instructions_not_liftable": sum(bad_insn.values()),
        "top_missing_instructions": bad_insn.most_common(40),
        "functions_blocked_by_mnemonic": bad_funcs_by_reason.most_common(40),
        "imports_total": len(pe.imports),
        "imports_supported": sum(supported(d, s) for _, d, s in pe.imports),
        "imports_by_dll": {d: len(v) for d, v in sorted(imports.items(), key=lambda kv: -len(kv[1]))},
        "pe_features_present": features,
    }
    print(json.dumps({k: v for k, v in rep.items() if k not in ("top_missing_instructions", "functions_blocked_by_mnemonic")}, indent=1))
    print("functions blocked, by mnemonic (a function can appear under several):")
    for r, n in bad_funcs_by_reason.most_common(40):
        print(f"  {n:6} {r}")
    if a.json:
        rep["imports"] = imports
        with open(a.json, "w") as f:
            json.dump(rep, f, indent=1)


if __name__ == "__main__":
    main()
