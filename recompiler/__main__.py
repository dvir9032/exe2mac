"""exe2mac command line.

    python3 -m recompiler translate test/hello.exe -o build/hello.gen.c
    python3 -m recompiler build     test/hello.exe -o build/hello
    python3 -m recompiler run       test/hello.exe [--expect-stdout FILE] [--expect-exit N]
"""
import argparse
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from .translate import TranslationError, build, translate


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m recompiler", description="exe2mac static recompiler")
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("translate", help="emit generated C")
    t.add_argument("exe")
    t.add_argument("-o", "--output", required=True)
    b = sub.add_parser("build", help="translate and compile a native executable")
    b.add_argument("exe")
    b.add_argument("-o", "--output", required=True)
    b.add_argument("--cc")
    r = sub.add_parser("run", help="build into a temp dir, run, optionally verify")
    r.add_argument("exe")
    r.add_argument("--cc")
    r.add_argument("--expect-stdout", help="file whose bytes stdout must equal")
    r.add_argument("--expect-exit", type=int)
    args = p.parse_args(argv)

    try:
        if args.cmd == "translate":
            Path(args.output).write_text(translate(args.exe))
            return 0
        if args.cmd == "build":
            out = build(args.exe, args.output, cc=args.cc)
            print(f"built {out} for {platform.system()} {platform.machine()}")
            return 0
        with tempfile.TemporaryDirectory() as td:
            exe = build(args.exe, os.path.join(td, "guest"), cc=args.cc)
            res = subprocess.run([str(exe)], capture_output=True)
        sys.stdout.buffer.write(res.stdout)
        sys.stderr.buffer.write(res.stderr)
        ok = True
        print(f"\n[exe2mac] host={platform.system()} {platform.machine()} exit={res.returncode}", file=sys.stderr)
        if args.expect_stdout is not None:
            same = Path(args.expect_stdout).read_bytes() == res.stdout
            print(f"[exe2mac] stdout byte-for-byte vs {args.expect_stdout}: {'MATCH' if same else 'MISMATCH'}",
                  file=sys.stderr)
            ok &= same
        if args.expect_exit is not None:
            same = res.returncode == args.expect_exit
            print(f"[exe2mac] exit code {res.returncode} vs expected {args.expect_exit}: {'MATCH' if same else 'MISMATCH'}",
                  file=sys.stderr)
            ok &= same
        if args.expect_stdout is None and args.expect_exit is None:
            return res.returncode
        return 0 if ok else 1
    except TranslationError as exc:
        print(f"exe2mac: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
