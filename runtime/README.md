# exe2mac runtime

| File | Role |
|---|---|
| `x86_cpu.h` | guest register file, flags, instruction-semantic helpers, condition codes, guest push/pop |
| `guest_mem.h/.c` | guest address space: regions, bounds/permission-checked little-endian access |
| `fault.c` | fatal guest faults (exit status = low byte of the NTSTATUS) |
| `exe2mac_rt.h` | interface between generated code and the runtime |
| `loader.c` | maps the image, applies relocations, binds the IAT, sets up the guest stack |
| `dispatch.c` | indirect-call targets outside translated code (import thunks), return-address checks |
| `winapi_bridge.c` | Windows x64 ABI → host bridges for the supported kernel32 imports (see `docs/TRANSLATION.md`) |
| `process.h/.c` | process heap, command line (Windows quoting), last-error value, VirtualAlloc regions |
| `guest_heap.h/.c` | first-fit allocator for the guest heap (host-side metadata) |
| `softfloat.h` | exact binary64/binary32 arithmetic with MXCSR rounding, FTZ/DAZ and exception flags |
| `x86_sse.h` | scalar SSE/SSE2 semantics on top of softfloat.h, MXCSR handling |
| `x86_simd.h` | packed SSE2 semantics (lane loops) |
| `winapi_shims.c/.h` | host POSIX implementations used by the bridges |
| `main.c` | process start-up for a translated program |

Guest addresses are never cast to host pointers; see `docs/TRANSLATION.md`.
