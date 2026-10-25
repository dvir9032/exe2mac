#!/bin/sh
# Build test/hello.exe into a native macOS ARM64 executable, run it, and
# compare stdout byte-for-byte with test/golden/hello.stdout and the exit code
# with 7. Run from the repository root on an Apple-silicon Mac:
#     sh scripts/verify_macos_arm64.sh
set -eu
os=$(uname -s); arch=$(uname -m)
echo "host: $os $arch"
if [ "$os" != "Darwin" ] || [ "$arch" != "arm64" ]; then
    echo "this script must run on macOS ARM64 (got $os $arch)" >&2
    exit 2
fi
python3 -c "import capstone" 2>/dev/null || { echo "missing: pip3 install capstone==5.0.3" >&2; exit 2; }
mkdir -p build
python3 -m recompiler build test/hello.exe -o build/hello
file build/hello
set +e
./build/hello > build/hello.stdout 2> build/hello.stderr
code=$?
set -e
echo "exit code: $code (expected 7)"
if cmp -s build/hello.stdout test/golden/hello.stdout; then echo "stdout: MATCH (byte-for-byte)"; else echo "stdout: MISMATCH"; diff build/hello.stdout test/golden/hello.stdout || true; fi
if [ -s build/hello.stderr ]; then echo "stderr (should be empty):"; cat build/hello.stderr; fi
python3 -m unittest discover -s tests -v
[ "$code" -eq 7 ] && cmp -s build/hello.stdout test/golden/hello.stdout && [ ! -s build/hello.stderr ]
