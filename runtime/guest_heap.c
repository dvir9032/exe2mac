#include "guest_heap.h"

#include <stdlib.h>
#include <string.h>

static int grow(guest_heap *h) {
    if (h->n < h->cap) return 0;
    unsigned cap = h->cap ? h->cap * 2 : 64;
    guest_heap_block *b = realloc(h->blocks, cap * sizeof *b);
    if (!b) return -1;
    h->blocks = b;
    h->cap = cap;
    return 0;
}

int guest_heap_init(guest_heap *h, guest_mem *m, uint64_t base, uint64_t size) {
    memset(h, 0, sizeof *h);
    h->host = calloc(1, size);
    if (!h->host || guest_map(m, base, size, h->host, GUEST_PERM_R | GUEST_PERM_W, "heap")) return -1;
    h->base = base;
    h->size = size;
    if (grow(h)) return -1;
    h->blocks[0] = (guest_heap_block){base, size, 0, 0};
    h->n = 1;
    return 0;
}

void guest_heap_destroy(guest_heap *h, guest_mem *m) {
    if (h->host) guest_unmap(m, h->base);
    free(h->host);
    free(h->blocks);
    memset(h, 0, sizeof *h);
}

static long find(const guest_heap *h, uint64_t va) {
    unsigned lo = 0, hi = h->n;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (h->blocks[mid].va < va) lo = mid + 1; else hi = mid;
    }
    return (lo < h->n && h->blocks[lo].va == va) ? (long)lo : -1;
}

static uint64_t round_up(uint64_t size) {
    if (size == 0) size = 1;                         /* HeapAlloc(0) returns a unique block */
    if (size > ~(uint64_t)0 - EXE2MAC_HEAP_ALIGN) return 0;
    return (size + EXE2MAC_HEAP_ALIGN - 1) & ~(uint64_t)(EXE2MAC_HEAP_ALIGN - 1);
}

/* split block i so that it is exactly `size` bytes; the rest becomes a free block */
static int split(guest_heap *h, unsigned i, uint64_t size) {
    if (h->blocks[i].size == size) return 0;
    if (grow(h)) return -1;
    memmove(&h->blocks[i + 2], &h->blocks[i + 1], (h->n - i - 1) * sizeof h->blocks[0]);
    h->blocks[i + 1] = (guest_heap_block){h->blocks[i].va + size, h->blocks[i].size - size, 0, 0};
    h->blocks[i].size = size;
    h->n++;
    return 0;
}

static void coalesce(guest_heap *h, unsigned i) {
    if (i + 1 < h->n && !h->blocks[i + 1].used) {
        h->blocks[i].size += h->blocks[i + 1].size;
        memmove(&h->blocks[i + 1], &h->blocks[i + 2], (h->n - i - 2) * sizeof h->blocks[0]);
        h->n--;
    }
    if (i > 0 && !h->blocks[i - 1].used) {
        h->blocks[i - 1].size += h->blocks[i].size;
        memmove(&h->blocks[i], &h->blocks[i + 1], (h->n - i - 1) * sizeof h->blocks[0]);
        h->n--;
    }
}

uint64_t guest_heap_alloc(guest_heap *h, uint64_t size, int zero) {
    uint64_t need = round_up(size);
    if (!need) return 0;
    for (unsigned i = 0; i < h->n; i++) {
        if (h->blocks[i].used || h->blocks[i].size < need) continue;
        if (split(h, i, need)) return 0;
        h->blocks[i].used = 1;
        h->blocks[i].req = size;
        if (zero) memset(h->host + (h->blocks[i].va - h->base), 0, need);
        return h->blocks[i].va;
    }
    return 0;
}

int guest_heap_free(guest_heap *h, uint64_t va) {
    long i = find(h, va);
    if (i < 0 || !h->blocks[i].used) return 0;
    h->blocks[i].used = 0;
    coalesce(h, (unsigned)i);
    return 1;
}

uint64_t guest_heap_block_size(const guest_heap *h, uint64_t va) {
    long i = find(h, va);
    return (i >= 0 && h->blocks[i].used) ? h->blocks[i].size : 0;
}

uint64_t guest_heap_realloc(guest_heap *h, uint64_t va, uint64_t size, int zero) {
    long i = find(h, va);
    if (i < 0 || !h->blocks[i].used) return 0;
    uint64_t need = round_up(size), old_req = h->blocks[i].req;
    if (!need) return 0;
    if (need <= h->blocks[i].size) {                  /* fits: stay in place */
        if (h->blocks[i].size != need) {
            if (split(h, (unsigned)i, need)) return 0;
            coalesce(h, (unsigned)i + 1);             /* merge the freed tail with a free neighbour */
        }
        h->blocks[i].req = size;
        if (zero && size > old_req) memset(h->host + (va - h->base) + old_req, 0, size - old_req);
        return va;
    }
    uint64_t nva = guest_heap_alloc(h, size, 0);
    if (!nva) return 0;
    memcpy(h->host + (nva - h->base), h->host + (va - h->base), old_req);
    if (zero) memset(h->host + (nva - h->base) + old_req, 0, size - old_req);
    guest_heap_free(h, va);
    return nva;
}
