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
python3 -m recompiler package   test/hello.exe -o dist --name Hello   # .app + .dmg (macOS)
python3 -m recompiler doctor                     # prerequisite check
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
* `jmp`/`jcc` → `goto` inside the C function. Tail calls out of a function and
  `ret imm16` are rejected.
* Jump tables: `cfg.py` recognises the bounded relative-offset idiom
  (`cmp idx, N; ja default; [mov r32, idx32]; lea B, [rip+T];
  movsxd R, [B + I*4]; add R, B; jmp R`) by symbolic evaluation of exactly
  these forms, takes the entry count from the bounds check, and reads the
  int32 entries from the image. It verifies after discovery that no other edge
  enters the sequence between the bounds check and the `jmp`. The translated
  code executes the real table load and add, then `switch`es on the computed
  guest VA over the proven targets; any other value (e.g. a table rewritten at
  run time) faults. Any other indirect `jmp` is rejected.
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
| `WriteFile(h, buf, DWORD, LPDWORD, LPOVERLAPPED)` | writes `buf[0..n)`; zeroes then stores bytes written; bad handle → FALSE + `ERROR_INVALID_HANDLE`; non-NULL OVERLAPPED faults |
| `ReadFile(h, buf, DWORD, LPDWORD, LPOVERLAPPED)` | standard input only; reads until the buffer is full or end of input (file semantics), TRUE with 0 bytes at EOF; other handles → FALSE + `ERROR_INVALID_HANDLE` |
| `GetCommandLineA()` | guest string built once from the host argv with the Windows quoting rules (inverse of `CommandLineToArgvW`); bytes passed through unchanged (ANSI) |
| `GetLastError()` / `SetLastError(DWORD)` | one per-process value (single-threaded guest) |
| `GetProcessHeap()` | handle 0x20000000 |
| `HeapAlloc` / `HeapReAlloc` / `HeapFree` | first-fit allocator over a 64 MiB guest region; 16-byte aligned; `HEAP_ZERO_MEMORY` (realloc zeroes beyond the previous request); metadata kept on the host so guest writes cannot corrupt it; bad free → FALSE + `ERROR_INVALID_PARAMETER`; other heaps / `HEAP_GENERATE_EXCEPTIONS` / `HEAP_REALLOC_IN_PLACE_ONLY` fault |
| `VirtualAlloc` / `VirtualFree` | `lpAddress == NULL`, `MEM_COMMIT\|MEM_RESERVE` (± `MEM_TOP_DOWN`), `PAGE_READWRITE`/`PAGE_READONLY` → zeroed, 64 KiB-aligned guest region; `MEM_RELEASE` of a whole region; other forms fault |
| `ExitProcess(UINT)` | `exit(code & 0xff)` (POSIX keeps 8 bits) |

Any other import is rejected at translation time and at load time.

## Supported instruction forms
Implemented exactly (defined flags computed; undefined flags left unchanged):

* data movement: `mov`/`movabs` (same width), `movsxd r64, r/m32`, `cdqe cwde`,
  `movzx`/`movsx` (r16/32/64 ← r/m8/16), `lea r16/32/64`, `xchg r, r/m`,
  `push r/m64/imm`, `pop r64`, `cmovcc` (all 16), `setcc r/m8` (all 16)
* arithmetic/logic: `add sub adc sbb and or xor` (r/m, r/m/imm), `cmp test`,
  `inc dec neg not`, `shl/sal shr sar` (imm8 or CL), `bt` (register or
  immediate offset; a memory bit string with a register offset is rejected), `mul r/m32|64`,
  `imul r, r/m` / `imul r, r/m, imm`, `div`/`idiv r/m32|64`
  (#DE → 0xC0000094 / 0xC0000095), `cdq cqo`
* strings: `rep stosb`, `rep movsb` (byte-exact, honours DF, overlap-safe)
* SSE/SSE2 (scalar): `addsd subsd mulsd divsd sqrtsd minsd maxsd`, `addss subss mulss divss`,
  `ucomisd comisd`, `cmpsd`/`cmpXXsd` (8 predicates), `cvtsi2sd` (r/m32|64),
  `cvttsd2si` (r32|64), `cvtsd2ss cvtss2sd`, `movsd movss movd movq`,
  128-bit moves `movaps movapd movdqa` (aligned) / `movups movupd movdqu`,
  bitwise `xorps/pd andps/pd andnps/pd orps/pd pxor pand pandn por`.
  Exact x86 rules are implemented in `runtime/x86_sse.h`: NaN propagation
  (first operand wins, quieted), QNaN indefinite `0xFFF8000000000000` for
  invalid operations, integer indefinite for NaN/out-of-range conversions,
  min/max operand selection, which part of the destination each form writes,
  and 16-byte alignment of legacy-SSE m128 operands (→ access violation).
  Assumes the default MXCSR (round-to-nearest, no FTZ/DAZ, exceptions masked);
  MXCSR is not modelled, so `ldmxcsr`/`stmxcsr`, `cvtsd2si` (current rounding
  mode), packed arithmetic and x87 are rejected. Generated C is compiled with
  `-ffp-contract=off`.
* control flow: `jcc` (all 16), `jmp rel`, `call rel/reg/mem`, `ret`,
  `nop` (any form; never touches memory)

Rejected with `TranslationError` (address + bytes in the message): anything else
(e.g. `rol/ror`, packed SSE arithmetic such as `punpcklbw`/`addps` — so
auto-vectorised code is not yet supported —, x87, `rep stosd`, `repne scasb`),
LOCK prefixes, address-size override, FS/GS segment overrides, absolute
`[disp32]` operands, one-operand `imul`, `ret imm16`, indirect `jmp` other than
recognised jump tables,
unsupported imports, code relocations.

## Fixtures
| Fixture | Built with | Expected | Golden provenance |
|---|---|---|---|
| `test/hello.exe` | supplied | exit 7 | source-derived, confirmed on Windows CI |
| `test/ops.exe` | `sh scripts/build_fixture.sh test/ops.c test/ops.exe` (clang + lld-link, -O2) | exit 102 | `test/golden/ops_model.py` (independent Python model of the C semantics) + Windows CI job |
| `test/switch.exe` | `sh scripts/build_fixture.sh test/switch.c test/switch.exe` | exit 50 | `test/golden/switch_model.py` + Windows CI job |
| `test/fp.exe` | `EXTRA_CFLAGS=-fno-math-errno sh scripts/build_fixture.sh test/fp.c test/fp.exe` | exit 27 | `test/golden/fp_model.py` (SDM NaN rules) + Windows CI job |
| `test/io.exe` | `EXTRA_CFLAGS="-fno-vectorize -fno-slp-vectorize" sh scripts/build_fixture.sh test/io.c test/io.exe` | exit 5 with args `alpha "b c" q\"uote "back\slash\\" ""` and stdin `test/golden/io.input` | `test/golden/io_model.py` + Windows CI job via `test/io.windows.bat` |

## Verification
* `tests/c/test_cpu.c`: SDM-derived expected values for every helper (any host).
* `tests/c/test_sse.c` (portable, SDM-derived) and `tests/c/diff_sse.c`
  (8.1 M cases vs the real SSE unit, x86 hosts only).
* `tests/c/diff_x86.c`: 5.8 M cases against the real CPU (x86-64 hosts only;
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
