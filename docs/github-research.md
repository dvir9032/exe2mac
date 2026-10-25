# External project research for exe2mac

Reviewed public project documentation on 2026-10-25.

- [N64Recomp](https://github.com/N64Recomp/N64Recomp): a useful architectural model for literal per-instruction C emission, per-function outputs, and a separate runtime. It targets N64 MIPS, so its instruction semantics are not reusable for x86-64. Its README describes C code generation from instructions and runtime-provided helpers.
- [Remill](https://github.com/lifting-bits/remill): a static binary translator that lifts x86/amd64 and other ISAs into LLVM bitcode. Best reference for instruction semantics and a possible future integration point if exe2mac chooses LLVM IR rather than maintaining a large handwritten C lifter.
- [Capstone](https://github.com/capstone-engine/capstone): multi-architecture disassembly library with structured instruction and operand details. A likely replacement for parsing `objdump` text. Enable detail mode when operand and implicit-register metadata are required; Capstone 2.x documents API changes, so pin and test a specific version.

Recommended incremental architecture:

1. Keep `pe.py` responsible for PE image parsing and imports/relocations.
2. Make the decoder return a stable structured instruction model (Capstone can provide this).
3. Build control-flow/reference analysis independently of semantic lowering (`analysis.py`).
4. Implement and test instruction semantics in small families, with explicit unsupported-instruction errors.
5. Keep host shims separate from guest ABI adaptation and guest address-space mapping.
6. Only package an application after fixture output and exit code match a trusted Windows run.

## Licensing caution

Review each dependency's current license and notice requirements before vendoring or linking it. This note is architectural guidance, not legal advice.
