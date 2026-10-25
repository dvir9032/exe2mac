# exe2mac translation pipeline

```
PE32+ file ──pe.py──▶ mapped image, imports, DIR64 relocations
          ──decoder.py (Capstone)──▶ typed instructions
          ──cfg.py──▶ reachable functions / blocks / call sites   (fails closed)
          ──lift_c.py──▶ generated C (one C function per guest function)
          ──host cc──▶ native executable (ARM64 on an Apple-silicon Mac)
```
No guest instruction is interpreted at run time. Each guest instruction
becomes straight-line C over an explicit guest state; the host compiler
produces native code (verified to emit ARM64 Mach-O, see below).

## Commands
```sh
pip install capstone==5.0.3                      # dependency (BSD-3-Clause)
python3 -m recompiler translate test/hello.exe -o build/hello.gen.c
python3 -m recompiler build     test/hello.exe -o build/hello
python3 -m recompiler run       test/hello.exe --expect-stdout test/golden/hello.stdout --expect-exit 7
python3 -m unittest discover -s tests -v
sh scripts/verify_macos_arm64.sh                 # on an Apple-silicon Mac
```
CI: `.github/workflows/macos-arm64.yml` runs the same script on GitHub's
Apple-silicon `macos-14` runner and uploads `verify.log` and `build/`.
Prerequisites: Python ≥ 3.10, a C11 compiler with `__int128` (clang or gcc),
Capstone Python bindings. On macOS: Xcode Command Line Tools.

## Guest state and memory
* `x86_state` (runtime/x86_cpu.h): 16 GPRs, RIP, CF/PF/AF/ZF/SF/OF/DF.
  Writes: 64-bit full, 32-bit zero-extends, 16/8-bit merge, AH/CH/DH/BH.
* Guest memory (runtime/guest_mem.*): region table of guest VAs. Every access
  is bounds-, wrap- and permission-checked; values are assembled little-endian
  byte by byte. Faults exit with the low byte of the Windows NTSTATUS
  (0xC0000005 → 5) and print the full code to stderr.
* Image: mapped at the preferred base by default (`EXE2MAC_IMAGE_BASE=<hex>`
  selects another 64 KiB-aligned base). Sections are mapped with their PE
  read/write permissions, rounded to SectionAlignment. DIR64 relocations are
  applied with `delta = actual − preferred`. Generated code addresses image
  data as `B + rva`, so it is base-independent. Relocations that patch code
  bytes are rejected at translation time (not needed by the fixture).
* Stack: 1 MiB at guest VA 0x10000000. At entry RSP ≡ 8 (mod 16), `[RSP]` holds
  an exit sentinel, and 32 bytes of home space lie above it.

## Calls, returns, indirect control flow
* `call rel32`: push guest return VA on the guest stack; call the callee's C
  function; check that its guest `ret` popped exactly that VA (`s->rip`).
  Host return addresses never enter guest memory.
* `ret`: `s->rip = pop64(); return;`
* Indirect `call reg/[mem]` (incl. IAT slots and the `ops[k]` table): the target
  is read from guest state/memory (before the push), then
  `exe2mac_dispatch()` switches on the guest VA: known function entries call
  their translated C function; import thunk VAs run the bridge; anything else
  faults.
* `jmp`/`jcc` → `goto` inside the C function. Indirect `jmp` (jump tables),
  tail calls out of a function, and `ret imm16` are rejected.
* `ExitProcess` is known not to return; code after it is not translated.

## Imports and the Windows x64 ABI bridge
IAT slots are filled by the loader with thunk VAs in a reserved, unmapped
window (`0x7ffe00000000 + 16·i`). A bridge is entered with the guest layout
of a real callee (args in RCX, RDX, R8, R9, `[RSP+0x28]`…, return address at
`[RSP]`), reads arguments at their declared C widths (DWORD = low 32 bits),
converts guest pointers via checked guest memory, calls the host shim, sets
RAX and performs the guest `ret`.

| Import | Behaviour |
|---|---|
| `GetStdHandle(DWORD)` | −10/−11/−12 → biased handle 0x1000+fd; other → INVALID_HANDLE_VALUE |
| `WriteFile(h, buf, DWORD, LPDWORD, LPOVERLAPPED)` | writes `buf[0..n)` to the fd; stores bytes written; non-NULL OVERLAPPED faults (unsupported) |
| `ExitProcess(UINT)` | `exit(code & 0xff)` (POSIX keeps 8 bits) |

Any other import is rejected at translation time and at load time.

## Supported instruction forms
Implemented exactly (defined flags computed; undefined flags left unchanged):

`mov`/`movabs` (r/m ← r/m/imm, same width), `movsxd r64, r/m32`, `lea r16/32/64`,
`add sub and or xor` (r/m, r/m/imm), `cmp test`, `inc dec neg`,
`shr r/m, imm8|CL`, `mul r/m32|64`, `imul r, r/m` and `imul r, r/m, imm`,
`idiv r/m32|64` (#DE → 0xC0000094 / 0xC0000095), `cdq cqo`, `cmovcc` (all 16
conditions), `jcc` (all 16), `jmp rel`, `call rel/reg/mem`, `ret`, `push r/m64/imm`,
`pop r64`, `nop` (any form; never touches memory).

Rejected with `TranslationError` (address + bytes in the message): anything else
(e.g. `movzx`, `xchg`, `shl`, `sar`, SSE/x87), LOCK/REP prefixes, address-size
override, FS/GS segment overrides, absolute `[disp32]` operands, one-operand
`imul`, `ret imm16`, indirect `jmp`, unsupported imports, code relocations.

## Verification
* `tests/c/test_cpu.c`: SDM-derived expected values for every helper (any host).
* `tests/c/diff_x86.c`: 2.4 M cases against the real CPU (x86-64 hosts only;
  test-only oracle, never part of a translated program). Mutation-checked.
* `tests/test_lifter.py`: lifted snippets compiled, executed, final state compared.
* `tests/test_bridge_c.py`: ABI bridge argument/return/stack behaviour and faults.
* `tests/test_e2e.py`: builds and **executes** translated `hello.exe` on the
  current host; stdout byte-for-byte vs `test/golden/hello.stdout`, empty
  stderr, exit code 7; rebased run; negative control without relocations;
  compile-only ARM64 Mach-O check.

## Limitations
* Only the instruction forms, imports and control flow listed above.
* No SEH/exception unwinding, TLS, threads, CRT start-up, or DLL loading.
* Exit status is 8 bits on POSIX.
* The CFG requires every indirect-call target to be a discovered function entry
  (entry point, direct call target, or a relocated code pointer).
