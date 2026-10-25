/* Guest image loader: maps the PE image into the guest address space,
 * applies DIR64 base relocations, binds the IAT to bridge thunks and creates
 * the guest stack with the Windows x64 entry-point layout. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exe2mac_rt.h"
#include "process.h"

uint64_t g_exe2mac_base;

static int fail(const char *msg, uint64_t a) {
    fprintf(stderr, "exe2mac: load error: %s (0x%" PRIx64 ")\n", msg, a);
    return -1;
}

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static int overlaps(uint64_t a, uint64_t alen, uint64_t b, uint64_t blen) {
    return a < b + blen && b < a + alen;
}

int exe2mac_load(x86_state *s, guest_mem *m, uint64_t base) {
    uint64_t size = exe2mac_image_size;
    if (base & 0xffffu) return fail("image base must be 64 KiB aligned", base);
    if (base + size < base) return fail("image range wraps", base);
    if (overlaps(base, size, EXE2MAC_STACK_BASE, EXE2MAC_STACK_SIZE))
        return fail("image overlaps guest stack", base);
    if (overlaps(base, size, EXE2MAC_THUNK_BASE, 0x100000000ull))
        return fail("image overlaps thunk window", base);
    if (overlaps(base, size, EXE2MAC_HEAP_BASE, EXE2MAC_HEAP_SIZE))
        return fail("image overlaps the guest heap", base);
    if (overlaps(base, size, EXE2MAC_VALLOC_BASE, EXE2MAC_VALLOC_LIMIT - EXE2MAC_VALLOC_BASE))
        return fail("image overlaps the VirtualAlloc window", base);

    uint8_t *img = malloc(size);
    if (!img) return fail("out of memory", size);
    memcpy(img, exe2mac_image_init, size);

    /* relocations: add (actual - preferred) modulo 2^64 */
    uint64_t delta = base - exe2mac_preferred_base;
    for (unsigned i = 0; i < exe2mac_nrelocs; i++) {
        uint64_t rva = exe2mac_relocs[i];
        if (rva > size || size - rva < 8) return fail("relocation outside image", rva);
        put64(img + rva, get64(img + rva) + delta);
    }

    /* imports: each IAT slot receives the guest VA of its bridge thunk */
    for (unsigned i = 0; i < exe2mac_nimports; i++) {
        const exe2mac_import *imp = &exe2mac_imports[i];
        int b = exe2mac_find_bridge(imp->dll, imp->name);
        if (b < 0) {
            fprintf(stderr, "exe2mac: load error: unsupported import %s!%s\n", imp->dll, imp->name);
            return -1;
        }
        if (imp->iat_rva > size || size - imp->iat_rva < 8) return fail("IAT slot outside image", imp->iat_rva);
        put64(img + imp->iat_rva, EXE2MAC_THUNK_BASE + (uint64_t)b * EXE2MAC_THUNK_STRIDE);
    }

    memset(m, 0, sizeof *m);
    if (guest_map(m, base, exe2mac_headers_size, img, GUEST_PERM_R, "headers"))
        return fail("cannot map headers", base);
    for (unsigned i = 0; i < exe2mac_nsections; i++) {
        const exe2mac_section *sec = &exe2mac_sections[i];
        if (sec->rva > size || size - sec->rva < sec->size) return fail("section outside image", sec->rva);
        if (guest_map(m, base + sec->rva, sec->size, img + sec->rva, sec->perms, sec->name))
            return fail("cannot map section (overlap?)", sec->rva);
    }

    uint8_t *stack = calloc(1, EXE2MAC_STACK_SIZE);
    if (!stack) return fail("out of memory", EXE2MAC_STACK_SIZE);
    if (guest_map(m, EXE2MAC_STACK_BASE, EXE2MAC_STACK_SIZE, stack, GUEST_PERM_R | GUEST_PERM_W, "stack"))
        return fail("cannot map stack", EXE2MAC_STACK_BASE);

    memset(s, 0, sizeof *s);
    s->mem = m;
    /* Entry layout per Windows x64 ABI: RSP = 8 (mod 16) after the caller's
     * CALL, return address at [RSP], 32-byte home space above it. */
    s->gpr[X86_RSP] = EXE2MAC_STACK_BASE + EXE2MAC_STACK_SIZE - 0x28;
    guest_st64(m, s->gpr[X86_RSP], EXE2MAC_EXIT_SENTINEL);
    s->df = 0;
    g_exe2mac_base = base;
    s->rip = base + exe2mac_entry_rva;
    return 0;
}
