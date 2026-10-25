"""exe2mac command line.

    python3 -m recompiler translate test/hello.exe -o build/hello.gen.c
    python3 -m recompiler build     test/hello.exe -o build/hello
    python3 -m recompiler run       test/hello.exe [--expect-stdout FILE] [--expect-exit N]
    python3 -m recompiler package   test/hello.exe -o dist [--name Hello] [--no-dmg] [--no-sign]
    python3 -m recompiler doctor
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
    k = sub.add_parser("package", help="build, wrap in a macOS .app, sign ad-hoc and make a .dmg (macOS)")
    k.add_argument("exe")
    k.add_argument("-o", "--output", required=True, help="output directory")
    k.add_argument("--name")
    k.add_argument("--no-dmg", action="store_true")
    k.add_argument("--no-sign", action="store_true")
    k.add_argument("--cc")
    sub.add_parser("doctor", help="check prerequisites")
    args = p.parse_args(argv)

    try:
        if args.cmd == "translate":
            Path(args.output).write_text(translate(args.exe))
            return 0
        if args.cmd == "doctor":
            from .package import doctor
            ok = True
            for name, good, detail in doctor():
                print(f"[{'ok' if good else 'MISSING'}] {name}: {detail}")
                ok &= good or name.startswith("host is")
            return 0 if ok else 1
        if args.cmd == "package":
            from .package import package
            res = package(args.exe, args.output, app_name=args.name, dmg=not args.no_dmg,
                          sign=not args.no_sign, cc=args.cc)
            print(f"app:    {res['app']}")
            print(f"signed: {res['signed']} (ad-hoc)")
            print(f"dmg:    {res['dmg'] or 'not created (needs macOS hdiutil or --no-dmg given)'}")
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
