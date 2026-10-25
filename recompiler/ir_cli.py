"""Generate a machine-readable instruction IR JSON report."""
import argparse
import json
from .ir import build_ir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", help="input PE32+ x86-64 executable")
    parser.add_argument("-o", "--output", help="output JSON path; defaults to stdout")
    parser.add_argument("--start", type=lambda x: int(x, 0))
    parser.add_argument("--end", type=lambda x: int(x, 0))
    args = parser.parse_args()
    data = build_ir(args.exe, args.start, args.end)
    rendered = json.dumps(data, indent=2) + "\n"
    if args.output:
        with open(args.output, "w") as f:
            f.write(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
