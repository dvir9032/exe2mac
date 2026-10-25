# Instruction IR export

`recompiler.ir.build_ir(path, start=None, end=None)` produces a JSON-serializable,
descriptive representation of the decoded PE code range.

The report preserves:
- instruction virtual address, size, exact encoding bytes, mnemonic, operands and next address;
- direct targets for calls and branches where objdump provides a direct address;
- RIP-relative memory references and resolved import address table symbols;
- the approximate basic-block graph from `recompiler.analysis`;
- PE imports and base-relocation RVAs.

Generate the fixture report:

```sh
python3 -m recompiler.ir_cli test/hello.exe -o test/hello-ir.json
```

This is not semantic lifting. The report does not prove that an instruction is
implemented, reachable, or safe to translate. The current CFG is an approximation,
and indirect-call targets such as `ops[k]` still need explicit data-flow and
dispatcher handling. Unknown or unsupported instructions must never be emitted
as no-ops.
