#!/bin/sh
# Build a CRT-free Windows x64 console fixture with clang + lld-link.
#   sh scripts/build_fixture.sh test/ops.c test/ops.exe
#   EXTRA_CFLAGS=-fno-math-errno sh scripts/build_fixture.sh test/fp.c test/fp.exe
# Requires clang and lld-link/llvm-dlltool (LLVM >= 15). Output is a PE32+
# image whose only imports come from test/kernel32.def.
set -eu
src=$1; out=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
LLVM_BIN=${LLVM_BIN:-$(dirname "$(command -v lld-link || echo /usr/lib/llvm-18/bin/lld-link)")}
"$LLVM_BIN/llvm-dlltool" -d test/kernel32.def -l "$tmp/kernel32.lib" -m i386:x86-64
clang -target x86_64-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector \
      -mno-stack-arg-probe ${EXTRA_CFLAGS:-} -c "$src" -o "$tmp/obj.obj"
"$LLVM_BIN/lld-link" /nologo /subsystem:console /entry:start /nodefaultlib \
      "$tmp/obj.obj" "$tmp/kernel32.lib" /out:"$out"
echo "built $out"
