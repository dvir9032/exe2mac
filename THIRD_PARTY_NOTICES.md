# Third-party software

| Project | Use in exe2mac | License (verified from the upstream LICENSE file, 2026-10-25) |
|---|---|---|
| [Capstone](https://github.com/capstone-engine/capstone) 5.0.3 | Runtime dependency of the translator (Python bindings) for x86-64 decoding. Not vendored; no Capstone code is copied. | BSD-3-Clause |
| [N64Recomp](https://github.com/N64Recomp/N64Recomp) | Architectural reference only (one C function per guest function, separate runtime). No code copied. | MIT |
| [Remill](https://github.com/lifting-bits/remill) | Reference for modelling x86 state and semantics. No code copied. | Apache-2.0 |

Translated executables link only exe2mac's own runtime (`runtime/`) and the host C library.
This table is engineering documentation, not legal advice.
