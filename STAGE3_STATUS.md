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

## Packaging (Task 6) — verified on macOS ARM64, run 40183160790
`python3 -m recompiler package test/hello.exe -o dist --name Hello` produces
`Hello.app` (console launcher + translated binary, ad-hoc signed,
`codesign --verify --deep --strict` passes) and `Hello.dmg` (UDZO, `hdiutil verify`).
Smoke test from the mounted image: exit 7, stdout MATCH, stderr empty. 79 tests OK (1 x86-only skip).
Distribution to other Macs would additionally need Developer ID signing and notarization.

## Windows reference — run 40183160790
Original `hello.exe` on `windows-latest` (10.0.26100, x86_64): exit 7, stdout
sha256 `37d9bd3aed0bb630037598a49e7e28780b658083cd50acf0ed9ca6ee541d34c2` = golden = translated output on macOS ARM64.

## Wave 2 coverage — run 40183855375 (2026-10-25)
New fixture `test/ops.exe` (source `test/ops.c`): movzx/movsx, shl/sar, div,
adc/sbb, not, setcc, xchg, rep stosb/movsb, movaps.
- Windows reference (original exe): exit 102, stdout sha256 `d3a074a4…` = golden (612 bytes)
- macOS ARM64 (macos-14): 86 tests OK (1 x86-only skip), including the ops end-to-end test
  (stdout byte-identical, exit 102, also when rebased)
- Linux x86-64: 86 tests OK; differential test 5,807,808 cases, 0 failures

## Not implemented
See "Limitations" in `docs/TRANSLATION.md`. 
