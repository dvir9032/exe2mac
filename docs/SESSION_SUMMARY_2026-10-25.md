# exe2mac — session summary (2026-10-25)

Audience: an engineer or AI agent continuing this project. Facts below were
verified by running commands; nothing is inferred from "code that looks right".

## Goal
Statically recompile Windows PE32+ x86-64 programs into native macOS ARM64
executables (no Wine, no CPU emulation at run time). First fixture:
`test/hello.exe` (source `test/hello.c`; expected exit code 7).

## Timeline
1. **Baseline.** Received a handoff zip (PE parser, objdump frontend, CFG
   approximation, WinAPI shims, `translate.py` that deliberately raised).
   7/7 tests passed. PyPI/apt were blocked in the agent environment; Capstone
   5.0.3 (BSD-3) was built from GitHub source. One inspection step was halted
   by an automated safety classifier; it was not repeated.
2. **User-supplied update** (`exe2mac_next.zip`) added `ir.py`/`ir_cli.py`.
   Bug found: `ir_cli.py` wrote a literal `\n`, producing invalid JSON
   (the checked-in `test/hello-ir.json` was also invalid). Fixed + regression test.
3. **Task 1 – decoder/IR/CFG.** `recompiler/decoder.py` (Capstone, typed
   operands, flags read/written), `recompiler/cfg.py` (recursive descent,
   fail-closed), `cfg_cli.py`. Fixture: 340 reachable instructions,
   7 functions, 3 direct / 5 import / 13 dynamic call sites, 33 mnemonics.
   Bug caught by tests: blocks after `call` were not split; fixed.
4. **Task 2 – guest CPU.** `runtime/x86_cpu.h` (registers, partial writes,
   exact flags, 16 conditions, mul/imul/idiv/cdq, push/pop),
   `runtime/guest_mem.*` (bounds/permission-checked LE memory),
   `runtime/fault.c` (NTSTATUS-style exits). 749 SDM-derived checks +
   2,406,540 differential cases vs the real x86 CPU, 0 failures;
   mutation-checked (4/4 mutants caught).
5. **Tasks 3–5 – lifter, loader, ABI, end-to-end.** `recompiler/lift_c.py`
   (one C function per guest function; guest call/ret on the guest stack with
   return-address verification; VA dispatcher for indirect calls),
   `runtime/loader.c` (section mapping, DIR64 relocations, IAT → thunk VAs,
   Windows x64 entry stack), `runtime/winapi_bridge.c` (GetStdHandle,
   WriteFile, ExitProcess), `runtime/dispatch.c`, `runtime/main.c`, CLI
   `python3 -m recompiler translate|build|run`. Lifter snippet tests were
   mutation-checked.
6. **macOS readiness.** Found that macOS `objdump` is llvm-objdump (7 legacy
   tests fail with it). `disasm.py` now requires GNU objdump explicitly;
   those tests skip with a visible reason otherwise.
7. **macOS ARM64 verification.** The "online macOS simulator" repo suggested
   by the user is a list of web UI mock-ups and cannot run binaries. Added
   `.github/workflows/macos-arm64.yml`. Repo creation by the agent was blocked
   by the environment's permission system; the user created
   `dvir9032/exe2mac` (private), the agent pushed. Logs/artifacts are on blob
   storage unreachable from the agent, so the workflow publishes results as
   check-run annotations (readable via the GitHub API).

## Verified results
| Where | What |
|---|---|
| Linux x86-64 (agent) | 74 tests OK (gcc and clang); translated hello: stdout byte-identical (149 B), stderr empty, exit 7; same when rebased to 0x7ff6a0000000; negative control without relocations faults (exit 5) |
| macOS ARM64 (GitHub Actions run 40182478848, macos-14, macOS 14.8.9, Apple M1 virtual) | `Mach-O 64-bit executable arm64`; exit 7; stdout MATCH byte-for-byte (sha256 prefix 37d9bd3aed0bb630); stderr 0 B; 74 tests OK, 1 skipped (x86-only differential oracle) |

8. **Task 6 – packaging.** `recompiler/package.py`, CLI `package`/`doctor`:
   `.app` (console launcher), ad-hoc codesign, UDZO `.dmg`; CI smoke-tests the
   app from the mounted image. A test wrongly expected byte-identical binaries
   after codesign; fixed to check signature + behaviour.
9. **Windows reference.** A `windows-reference` CI job runs the original
   `hello.exe`. First attempts reported MISMATCH: the Windows checkout had
   converted the golden file to CRLF. Fixed with `.gitattributes`. Result:
   Windows output == golden == translated macOS output (run 40183160790).

10. **Wave 2 coverage.** New fixture `test/ops.c` → `test/ops.exe` built with
    clang + lld-link (`scripts/build_fixture.sh`). Added exact helpers, lifter forms
    and tests for movzx/movsx, shl/sar, div, adc/sbb, not, setcc, xchg,
    rep stosb/movsb, movaps (XMM state). Golden from an independent Python model
    (one formatting slip in the model fixed after comparison; all values matched),
    then confirmed by the Windows CI run (exit 102, identical sha256).

11. **Jump tables.** `cfg.py` recognises the bounded relative-offset switch
    idiom symbolically (count from `cmp`/`ja`, post-check that nothing bypasses
    the guard); the lifter runs the real table load and switches over proven
    targets, faulting otherwise. Fixture `test/switch.exe` (exit 50) matches its
    model and the Windows run; 95 tests pass on Linux and macOS ARM64.

12. **Scalar SSE.** `runtime/x86_sse.h` implements bit-exact scalar SSE/SSE2
    with explicit x86 NaN/indefinite rules (ARM64 differs natively); lifter
    covers the forms clang emits for `test/fp.c`. A surviving mutant showed that
    an x86 differential test cannot catch the ARM64 saturating float->int cast,
    so portable SDM-derived tests were added (they run on the macOS runner).
    `fp.exe` (exit 27, 1681 bytes) matches its model and the Windows run.

13. **kernel32 wave.** Process heap (first-fit, host-side metadata), command
    line from argv with Windows quoting, last-error value, VirtualAlloc regions,
    ReadFile from stdin; `bt`, `cdqe`/`cwde`. Fixture `test/io.exe` with arguments
    and stdin matches its model and the Windows run (exit 5, 273 bytes). clang
    auto-vectorised one loop (packed SSE, unsupported → translation stopped as
    intended), so this fixture is built with `-fno-vectorize -fno-slp-vectorize`.

## Open items / caveats
- Golden output now confirmed on Windows (see `test/golden/README.md`).
- Undefined x86 flags are left unchanged (a legal outcome).
- Unsupported (fail closed): see `docs/TRANSLATION.md` — e.g. movzx, xchg,
  shl/sar, SSE/x87, REP/LOCK, FS/GS, indirect jmp, ret imm16, other imports,
  relocations inside code, SEH/TLS/threads.
- POSIX exit status keeps 8 bits of the Windows exit code.

## Where to look
`STAGE3_STATUS.md` (status), `docs/TRANSLATION.md` (design, supported forms,
limitations), `docs/DECODER_CFG.md`, `runtime/README.md`,
`THIRD_PARTY_NOTICES.md` (Capstone BSD-3 dependency; N64Recomp MIT and
Remill Apache-2.0 used only as architectural references, no code copied).

## Next step
Packed SSE2 integer/FP instructions so auto-vectorised code translates;
then tail calls between functions, MXCSR modelling.
