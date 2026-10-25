# exe2mac status (2026-10-25)

## Implemented and tested
- PE32+ parsing; objdump frontend (unchanged) and Capstone structured decoder.
- Recursive-descent CFG over reachable code; fails closed on unmodelled control flow.
- Guest CPU semantics in C (`runtime/x86_cpu.h`), guest memory with bounds and
  permission checks, guest stack, faults with NTSTATUS-style exit codes.
- Loader: section mapping, DIR64 relocations (incl. non-preferred base), IAT
  bound to bridge thunks, Windows x64 entry stack layout.
- Windows x64 ABI bridges: GetStdHandle, WriteFile, ExitProcess.
- C lifter for every reachable instruction of `test/hello.exe` (340 instructions,
  7 functions) and a CLI: `python3 -m recompiler translate|build|run`.

## Verified results — Linux x86-64 host
- `python3 -m unittest discover -s tests -v`: 74 tests, all pass (gcc and clang).
- The translated `hello.exe` was built and **executed on Linux x86-64**:
  stdout byte-identical to `test/golden/hello.stdout` (149 bytes), stderr empty,
  exit code 7; same result when loaded at base 0x7ff6a0000000.
- The generated C compiles (compile-only, no link/run) to an arm64 Mach-O
  object with `clang -target arm64-apple-macos11`.

## Verified on macOS ARM64 (GitHub Actions, 2026-10-25)
Run 40182478848 of `.github/workflows/macos-arm64.yml`, commit 044c9bd, runner `macos-14`:
- host: Darwin arm64, macOS 14.8.9, Apple M1 (Virtual)
- binary: `Mach-O 64-bit executable arm64`, built by `python3 -m recompiler build`
- **executed**: exit code 7 (expected 7); stdout MATCH byte-for-byte with
  `test/golden/hello.stdout` (149 bytes, sha256 prefix 37d9bd3aed0bb630); stderr 0 bytes
- tests: 74 run, OK, 1 skipped (`diff_x86.c` differential oracle needs an x86-64 CPU)
- GNU binutils from Homebrew supported pei-x86-64, so the legacy objdump tests ran.

## Still open
- Golden stdout is source-derived, not captured on Windows (see `test/golden/README.md`).

## Not implemented
See "Limitations" in `docs/TRANSLATION.md`. Packaging (.app/.dmg) is Task 6 and
should start only after macOS execution is verified.
