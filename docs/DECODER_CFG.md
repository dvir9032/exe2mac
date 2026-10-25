# Structured decoder and reachable CFG

## Decoder — `recompiler/decoder.py`
Capstone 5.0.3 (BSD-3-Clause) is used as an external dependency; no Capstone
source is vendored. Install: `pip install capstone==5.0.3` (or build from
source as described in `docs/BASELINE_2026-10-25.md`). If it is missing,
`DecoderUnavailable` is raised; nothing falls back silently.

Each `Instruction` carries address, size, exact bytes, mnemonic, typed
operands, prefixes, control-flow class (`none`, `jump`, `cond_branch`,
`call`, `ret`, `trap`), direct target, indirect flag, implicit/explicit
registers read/written, and EFLAGS tested/modified/undefined (from Capstone).

Operands are `reg` (with GPR hardware index 0–15, width, high-8 flag),
`imm` (value after sign/zero extension, masked to the operand size), or
`mem` (segment, base, index, scale, signed displacement, and the absolute
`rip_target` for RIP-relative addressing). Non-GPR registers are `kind="other"`
so the lifter can reject them.

The objdump decoder in `disasm.py` is kept unchanged; a test checks that
Capstone and objdump agree on boundaries and bytes for every reachable
instruction of the fixture.

## CFG — `recompiler/cfg.py`
Recursive descent from the entry point, direct call targets, and code
pointers found through DIR64 relocations. Fails closed (`CFGError`) on
unresolved indirect jumps, control flow leaving executable sections,
overlapping decodes, or running past the end of `.text`.

Indirect calls are classified as `import` (memory operand is an IAT slot),
or `dynamic` (register / non-IAT memory). Dynamic calls are resolved at run
time by a guest-VA dispatcher in the generated program. `ExitProcess` is
treated as non-returning.

```sh
python3 -m recompiler.cfg_cli test/hello.exe -o test/hello-cfg.json
```

Fixture result: 340 reachable instructions in 7 functions (start, fib, sort,
op_add, op_mul, op_sub, op_div); 3 direct calls, 5 import calls, 13 dynamic
calls. The 18 instructions in the linear sweep that are not reachable are
the epilogue of `start` after `ExitProcess` and inter-function padding.

Reachable mnemonics (the real lifting work list): add, call, cdq, cmovs, cmp,
dec, idiv, imul, inc, ja, jae, jb, je, jg, jle, jmp, jne, jns, lea, mov,
movabs, movsxd, mul, neg, nop, or, pop, push, ret, shr, sub, test, xor.
(Capstone decodes `66 90` as `nop`; objdump prints it as `xchg ax,ax`.)
