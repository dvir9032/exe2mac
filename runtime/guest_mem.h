/* exe2mac guest address space.
 *
 * Guest virtual addresses (VAs) are plain uint64_t values in the guest's own
 * address space. They are never cast to host pointers directly: every access
 * goes through guest_ptr(), which finds the owning region, checks
 * bounds (including wrap-around) and permissions, and only then returns a host
 * pointer into that region's backing buffer.
 *
 * Multi-byte values are little-endian, assembled byte by byte, so the code is
 * correct regardless of host endianness and alignment.
 */
#ifndef EXE2MAC_GUEST_MEM_H
#define EXE2MAC_GUEST_MEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GUEST_PERM_R 1u
#define GUEST_PERM_W 2u
#define GUEST_MAX_REGIONS 64

typedef struct guest_region {
    uint64_t base;
    uint64_t size;
    uint8_t *host;
    unsigned perms;
    const char *name;
} guest_region;

typedef struct guest_mem {
    guest_region r[GUEST_MAX_REGIONS];
    int n;
} guest_mem;

/* Returns 0 on success, -1 if the region overlaps another, wraps, or the table is full. */
int guest_map(guest_mem *m, uint64_t base, uint64_t size, uint8_t *host, unsigned perms, const char *name);

/* Removes the region that starts exactly at `base`. Returns 0, or -1 if none. */
int guest_unmap(guest_mem *m, uint64_t base);

/* Bounds- and permission-checked translation. Faults (does not return) on failure. */
uint8_t *guest_ptr(guest_mem *m, uint64_t va, uint64_t len, unsigned need);

/* Same check without faulting: returns NULL on failure. */
uint8_t *guest_try_ptr(guest_mem *m, uint64_t va, uint64_t len, unsigned need);

_Noreturn void exe2mac_mem_fault(uint64_t va, uint64_t len, unsigned need);

static inline uint64_t guest_ld(guest_mem *m, uint64_t va, unsigned bytes) {
    const uint8_t *p = guest_ptr(m, va, bytes, GUEST_PERM_R);
    uint64_t v = 0;
    for (unsigned i = 0; i < bytes; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static inline void guest_st(guest_mem *m, uint64_t va, uint64_t v, unsigned bytes) {
    uint8_t *p = guest_ptr(m, va, bytes, GUEST_PERM_W);
    for (unsigned i = 0; i < bytes; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static inline uint64_t guest_ld8 (guest_mem *m, uint64_t va) { return guest_ld(m, va, 1); }
static inline uint64_t guest_ld16(guest_mem *m, uint64_t va) { return guest_ld(m, va, 2); }
static inline uint64_t guest_ld32(guest_mem *m, uint64_t va) { return guest_ld(m, va, 4); }
static inline uint64_t guest_ld64(guest_mem *m, uint64_t va) { return guest_ld(m, va, 8); }
static inline void guest_st8 (guest_mem *m, uint64_t va, uint64_t v) { guest_st(m, va, v, 1); }
static inline void guest_st16(guest_mem *m, uint64_t va, uint64_t v) { guest_st(m, va, v, 2); }
static inline void guest_st32(guest_mem *m, uint64_t va, uint64_t v) { guest_st(m, va, v, 4); }
static inline void guest_st64(guest_mem *m, uint64_t va, uint64_t v) { guest_st(m, va, v, 8); }

#ifdef __cplusplus
}
#endif
#endif
