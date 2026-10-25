"""Emit a JSON control-flow/reference report for a PE executable."""
import argparse
import json
from pathlib import Path
from .pe import PE
from .analysis import analyze

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", help="input PE32+ x86-64 executable")
    parser.add_argument("--start", type=lambda x: int(x, 0), help="start VA (default: PE entry point)")
    parser.add_argument("--end", type=lambda x: int(x, 0), help="exclusive end VA")
    parser.add_argument("-o", "--output", help="output JSON file (default: stdout)")
    args = parser.parse_args()
    pe = PE(args.exe)
    result = analyze(args.exe, pe, args.start, args.end)
    rendered = json.dumps(result.to_dict(), indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n")
    else:
        print(rendered)

if __name__ == "__main__":
    main()
