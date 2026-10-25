/* Interface between a generated (translated) program and the exe2mac runtime.
 *
 * The generator emits the image description below plus one C function per
 * guest function and the guest-VA dispatcher. The runtime provides the loader,
 * guest stack, import bridges and process start-up.
 */
#ifndef EXE2MAC_RT_H
#define EXE2MAC_RT_H

#include <stdint.h>
#include "x86_cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- emitted by the generator ------------------------------------------- */
typedef struct exe2mac_section {
    uint32_t rva;
    uint32_t size;        /* mapped size, already rounded to SectionAlignment */
    unsigned perms;       /* GUEST_PERM_* */
    const char *name;
} exe2mac_section;

typedef struct exe2mac_import {
    uint32_t iat_rva;
    const char *dll;      /* lower-case */
    const char *name;
} exe2mac_import;

extern const uint8_t exe2mac_image_init[];   /* mapped image at preferred base, unrelocated */
extern const uint32_t exe2mac_image_size;
extern const uint32_t exe2mac_headers_size;
extern const uint64_t exe2mac_preferred_base;
extern const uint32_t exe2mac_entry_rva;
extern const exe2mac_section exe2mac_sections[];
extern const unsigned exe2mac_nsections;
extern const uint32_t exe2mac_relocs[];      /* IMAGE_REL_BASED_DIR64 RVAs */
extern const unsigned exe2mac_nrelocs;
extern const exe2mac_import exe2mac_imports[];
extern const unsigned exe2mac_nimports;

/* Generated: call the translated guest function whose entry VA is `target`.
 * Unknown targets are forwarded to exe2mac_dispatch_external(). */
void exe2mac_dispatch(x86_state *s, uint64_t target);

/* ---- provided by the runtime --------------------------------------------- */
extern uint64_t g_exe2mac_base;              /* actual guest load base */

/* Guest VAs of import thunks live in a reserved window that is not mapped as
 * guest memory: calling one runs the host bridge, reading one faults. */
#define EXE2MAC_THUNK_BASE    0x00007ffe00000000ull
#define EXE2MAC_THUNK_STRIDE  16u
#define EXE2MAC_EXIT_SENTINEL 0x00007ffeffff0000ull   /* return address given to the entry point */

#define EXE2MAC_STACK_BASE    0x0000000010000000ull
#define EXE2MAC_STACK_SIZE    (1024u * 1024u)

void exe2mac_dispatch_external(x86_state *s, uint64_t target);
_Noreturn void exe2mac_bad_return(x86_state *s, uint64_t expected);
_Noreturn void exe2mac_noreturn_returned(x86_state *s, uint64_t call_site);

/* Loader: maps image + stack, applies relocations, binds the IAT.
 * Returns 0 on success, otherwise prints a diagnostic and returns -1. */
int exe2mac_load(x86_state *s, guest_mem *m, uint64_t base);

/* Import bridges (runtime/winapi_bridge.c). */
typedef void (*exe2mac_bridge_fn)(x86_state *s);
typedef struct exe2mac_bridge {
    const char *dll;
    const char *name;
    exe2mac_bridge_fn fn;
} exe2mac_bridge;
extern const exe2mac_bridge exe2mac_bridges[];
extern const unsigned exe2mac_nbridges;
int exe2mac_find_bridge(const char *dll, const char *name);   /* index or -1 */

#ifdef __cplusplus
}
#endif
#endif
