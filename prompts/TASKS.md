# Agent task sequence

Use these as separate prompts if the coding agent works better with scoped tasks. The master prompt in `MASTER_PROMPT_HE.md` always applies.

## Task 1 — Verify baseline and build a real IR
Inspect the complete repository and `test/hello.c`. Run the existing test suite. Produce a structured instruction representation with mnemonic, operands, widths, address, bytes, branch targets, RIP-relative targets and source locations. Prefer Capstone if available and document dependency installation; otherwise maintain a decoder interface around the current objdump parser. Add tests for operand parsing and CFG edges. Do not implement guessed instruction semantics.

Acceptance: existing tests remain passing; new decoder/IR tests pass; a machine-readable IR/CFG report is generated for `hello.exe`.

## Task 2 — Implement guest CPU primitives
Implement and test x86-64 guest register access, 8/16/32/64-bit writes and zero extension, guest memory accesses, guest stack, arithmetic flag helpers and condition evaluation. Add focused tests for CF/PF/AF/ZF/SF/OF and all Jcc conditions used by the fixture. Avoid signed-overflow UB in C.

Acceptance: isolated semantic unit tests pass, including edge cases and negative values.

## Task 3 — Translate reachable fixture instructions
Use the actual reachable-instruction set from `hello.exe`, not just a guessed mnemonic list. Implement the smallest correct subset required by reachable paths. Emit C or LLVM IR with basic blocks and explicit control flow. Unsupported reachable instructions must stop compilation with an actionable error. Add differential tests against small reference cases.

Acceptance: generated output is deterministic; no unsupported reachable instruction is silently ignored; generated code compiles on the available host.

## Task 4 — PE guest memory, relocations, imports and ABI bridge
Implement mapped guest image/section semantics and relocation handling. Implement import resolution and a deliberate bridge between guest Windows x64 ABI and host ABI. Do not call guest code as if it were a normal host function. Test each import shim and indirect call dispatch.

Acceptance: imports resolve to explicit stubs; invalid addresses/relocations fail clearly; tests cover stack/register arguments and return values.

## Task 5 — End-to-end hello fixture
Implement a single build/run CLI and golden-output test. Verify source-derived expected output and exit code. On macOS ARM64, compile and execute the generated native artifact; compare stdout byte-for-byte and exit code. If the agent host cannot run macOS ARM64 binaries, mark that specific test pending and provide exact commands for the user to run on their Mac.

Acceptance: no unsupported feature is hidden; output and exit code are documented with actual captured results.

## Task 6 — Packaging and release readiness
Only after end-to-end execution works, add macOS `.app` and `.dmg` packaging, reproducible build steps, dependency checks, license notices, and a smoke test. Keep packaging separate from translation correctness.

Acceptance: a clean checkout can run documented commands; app/dmg are produced and validated on macOS; limitations are explicit.
