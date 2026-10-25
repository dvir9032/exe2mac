#include "guest_mem.h"

static int range_ok(uint64_t base, uint64_t size) {
    return size != 0 && base + size - 1 >= base;   /* no wrap-around */
}

int guest_map(guest_mem *m, uint64_t base, uint64_t size, uint8_t *host, unsigned perms, const char *name) {
    if (m->n >= GUEST_MAX_REGIONS || !host || !range_ok(base, size)) return -1;
    uint64_t last = base + size - 1;
    for (int i = 0; i < m->n; i++) {
        uint64_t olast = m->r[i].base + m->r[i].size - 1;
        if (base <= olast && m->r[i].base <= last) return -1;
    }
    m->r[m->n++] = (guest_region){base, size, host, perms, name};
    return 0;
}

uint8_t *guest_try_ptr(guest_mem *m, uint64_t va, uint64_t len, unsigned need) {
    if (len == 0) len = 1;                      /* a zero-length access still needs a valid address */
    if (va + len - 1 < va) return NULL;         /* wraps */
    for (int i = 0; i < m->n; i++) {
        guest_region *r = &m->r[i];
        if (va >= r->base && va - r->base < r->size && len <= r->size - (va - r->base)) {
            if ((r->perms & need) != need) return NULL;
            return r->host + (va - r->base);
        }
    }
    return NULL;
}

uint8_t *guest_ptr(guest_mem *m, uint64_t va, uint64_t len, unsigned need) {
    uint8_t *p = guest_try_ptr(m, va, len, need);
    if (!p) exe2mac_mem_fault(va, len, need);
    return p;
}
