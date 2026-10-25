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

## Verified results — Linux x86-64 host only
- `python3 -m unittest discover -s tests -v`: 74 tests, all pass (gcc and clang).
- The translated `hello.exe` was built and **executed on Linux x86-64**:
  stdout byte-identical to `test/golden/hello.stdout` (149 bytes), stderr empty,
  exit code 7; same result when loaded at base 0x7ff6a0000000.
- The generated C compiles (compile-only, no link/run) to an arm64 Mach-O
  object with `clang -target arm64-apple-macos11`.

## Not yet verified
- **macOS ARM64 execution has not been performed.** Either push the repository to
  GitHub (workflow `.github/workflows/macos-arm64.yml` runs on an Apple-silicon
  `macos-14` runner) or run `sh scripts/verify_macos_arm64.sh` on an Apple-silicon Mac.
- On macOS, `objdump` is llvm-objdump; the legacy objdump-frontend tests (7) need GNU
  binutils and are skipped with a visible reason without it. The translator uses Capstone.
- Golden stdout is source-derived, not captured on Windows (see `test/golden/README.md`).

## Not implemented
See "Limitations" in `docs/TRANSLATION.md`. Packaging (.app/.dmg) is Task 6 and
should start only after macOS execution is verified.
