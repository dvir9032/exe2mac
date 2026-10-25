# Instructions for AI coding agents working on exe2mac

## Mission
Implement `exe2mac`: static recompilation of supported Windows PE32+ x86-64 programs into native macOS ARM64 executables, without running the guest program under Wine or a CPU emulator. Start with `test/hello.exe`, whose source is `test/hello.c`.

## Non-negotiable engineering rules
1. Never claim the translated fixture works unless the generated native binary was actually built and run on a compatible macOS ARM64 host and its stdout/stderr/exit status were captured.
2. Fail closed on unsupported instructions, imports, relocations, or control-flow patterns. Never silently emit a no-op for unknown semantics.
3. Keep guest x86-64 state separate from the host ABI. Model guest registers, flags, memory, stack, and Windows x64 calling convention explicitly.
4. Use exact-width unsigned operations for bit-level semantics; avoid C signed-overflow undefined behavior. Handle 8/16/32/64-bit registers and x86 zero-extension rules explicitly.
5. Add focused unit tests for each instruction semantic and integration tests for every milestone.
6. Do not use generated host assembly or an emulator as a substitute for static recompilation. LLVM IR is acceptable as an intermediate representation; native machine code must be generated for the host.
7. Document assumptions, limitations, and platform-specific steps. Keep the existing PE/disassembly frontend intact unless tests demonstrate a bug.
8. Respect third-party licenses. Do not copy large code chunks from N64Recomp, Remill, or Capstone. Prefer using Capstone as a dependency and learn architectural patterns from public projects.

## Current repo state
- Pipeline: `pe.py` → `decoder.py` (Capstone) → `cfg.py` → `lift_c.py` → host C compiler; CLI `python3 -m recompiler`.
- Runtime: `runtime/` (see `runtime/README.md`); design and supported forms: `docs/TRANSLATION.md`.
- `test/hello.exe` translates, builds and runs correctly on Linux x86-64 (stdout byte-identical, exit 7).
  macOS ARM64 execution is still pending — see `STAGE3_STATUS.md`.
- Tests: `python3 -m unittest discover -s tests -v` (74 tests in the prepared Linux environment).

## Definition of done for the first useful milestone
- Translate the reachable code of `test/hello.exe` into generated C or LLVM IR and then native ARM64 code.
- Correctly model every instruction actually reachable in the fixture, including its flags, widths, stack operations, arithmetic, branches, calls, and returns.
- Resolve imports for `GetStdHandle`, `WriteFile`, and `ExitProcess` with a correct Windows x64-to-host ABI bridge.
- Apply relocations and preserve guest virtual-address semantics for code/data references.
- Have a repeatable command to build and run on macOS ARM64.
- Compare stdout byte-for-byte against an explicitly checked-in golden file based on the expected output of `test/hello.c`; verify the expected exit code (inspect source first—do not assume it without checking).
- Tests pass; docs explain supported instructions, unsupported cases, build prerequisites, and actual test environment.

## Required workflow
1. Inspect all relevant files before editing. Read `test/hello.c`, inspect the PE imports/sections/relocations and disassembly.
2. Run the existing tests and record baseline.
3. Write a short implementation plan and identify semantic risks before major changes.
4. Implement in small increments; run tests after each increment.
5. Add unit tests before or alongside instruction implementations.
6. Do not label a test as an integration test if it does not execute the generated program.
7. At the end, report: files changed, commands run, exact pass/fail counts, target OS/architecture, whether generated binary was actually executed, stdout comparison result, exit status, and known limitations.
8. If the environment is Linux or x86-64 and cannot execute/build the macOS ARM64 output, implement portable generator tests and clearly mark macOS runtime validation as pending. Never fabricate it.

## Architecture guidance
- Prefer a structured decoder (Capstone Python bindings or a small decoder abstraction that can later switch to Capstone) over parsing `objdump` presentation strings throughout the codebase.
- Prefer an explicit IR with typed operands and basic blocks. A C backend can be the first backend; design it so LLVM IR can be added later.
- A practical first implementation may use a guest address-space buffer and guest virtual addresses represented as offsets/addresses, but every memory access must be bounds-checked. Explain how PE preferred image base, image size, section mapping, imports, and relocations are handled.
- Define precise helper functions for flags (`CF`, `PF`, `AF`, `ZF`, `SF`, `OF`) and condition evaluation. Implement only flags needed by supported instructions, but compute them correctly.
- `call`/`ret` and indirect control flow must use a consistent guest stack/return-address model. Do not mix guest return addresses with native host return addresses.
- Keep Windows API shims separate from instruction semantics. Model `GetStdHandle`, `WriteFile`, and `ExitProcess` at the import boundary.
