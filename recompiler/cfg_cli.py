"""Emit the reachable-code CFG (Capstone decoder, recursive descent) as JSON."""
import argparse
import json
import sys

from .cfg import CFGError, discover
from .decoder import DecodeError, DecoderUnavailable
from .pe import PE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", help="input PE32+ x86-64 executable")
    parser.add_argument("-o", "--output", help="output JSON path; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        prog = discover(PE(args.exe))
    except (CFGError, DecodeError, DecoderUnavailable) as exc:
        print(f"exe2mac: {exc}", file=sys.stderr)
        return 2
    data = {"format": "exe2mac-cfg-v1", "input": args.exe, **prog.to_dict()}
    rendered = json.dumps(data, indent=2) + "\n"
    if args.output:
        with open(args.output, "w") as f:
            f.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
