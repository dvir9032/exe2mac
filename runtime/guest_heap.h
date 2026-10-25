/* Guest heap: a first-fit allocator over one guest memory region. Block
 * metadata is kept on the host side, so guest writes (even out-of-bounds
 * ones inside the region) can never corrupt the allocator. */
#ifndef EXE2MAC_GUEST_HEAP_H
#define EXE2MAC_GUEST_HEAP_H
#include <stdint.h>
#include "guest_mem.h"

#define EXE2MAC_HEAP_ALIGN 16u

typedef struct guest_heap_block { uint64_t va, size, req; int used; } guest_heap_block;  /* req: bytes requested */
typedef struct guest_heap {
    uint64_t base, size;
    uint8_t *host;
    guest_heap_block *blocks;     /* sorted by va, covering [base, base+size) exactly */
    unsigned n, cap;
} guest_heap;

int guest_heap_init(guest_heap *h, guest_mem *m, uint64_t base, uint64_t size);
void guest_heap_destroy(guest_heap *h, guest_mem *m);                       /* unmaps and frees */
uint64_t guest_heap_alloc(guest_heap *h, uint64_t size, int zero);        /* 0 on failure */
int guest_heap_free(guest_heap *h, uint64_t va);                           /* 1 ok, 0 not a live block */
uint64_t guest_heap_realloc(guest_heap *h, uint64_t va, uint64_t size, int zero); /* 0 on failure (old block kept) */
uint64_t guest_heap_block_size(const guest_heap *h, uint64_t va);          /* 0 if not a live block */
#endif
