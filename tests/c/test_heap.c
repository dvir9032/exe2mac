/* Guest heap allocator and command-line quoting tests (portable). */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "runtime/process.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); checks++; if (_a != _b) { failures++; \
    fprintf(stderr, "%s:%d: %s == 0x%" PRIx64 ", expected 0x%" PRIx64 "\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)

static guest_mem m;
static guest_heap h;
#define BASE 0x20000000ull
#define SIZE 0x10000ull

static void invariants(void) {
    uint64_t at = BASE;
    for (unsigned i = 0; i < h.n; i++) {
        CHECK(h.blocks[i].va == at);                       /* contiguous, sorted */
        CHECK(h.blocks[i].size > 0 && h.blocks[i].size % 16 == 0);
        if (i > 0) CHECK(h.blocks[i].used || h.blocks[i - 1].used);   /* free blocks coalesced */
        at += h.blocks[i].size;
    }
    EQ(at, BASE + SIZE);
}

static void test_basic(void) {
    memset(&m, 0, sizeof m);
    CHECK(guest_heap_init(&h, &m, BASE, SIZE) == 0);
    uint64_t a = guest_heap_alloc(&h, 1, 0), b = guest_heap_alloc(&h, 0, 0), c = guest_heap_alloc(&h, 100, 1);
    CHECK(a && b && c && a != b && b != c);
    EQ(a % 16, 0); EQ(b % 16, 0); EQ(c % 16, 0);
    EQ(guest_heap_block_size(&h, c), 112);
    uint8_t *pc = guest_ptr(&m, c, 100, GUEST_PERM_R);
    int zero = 1; for (int i = 0; i < 100; i++) zero &= pc[i] == 0;
    CHECK(zero);
    CHECK(guest_heap_free(&h, b));
    CHECK(!guest_heap_free(&h, b));                        /* double free rejected */
    CHECK(!guest_heap_free(&h, c + 16));                   /* interior pointer rejected */
    invariants();
    /* realloc grows and preserves contents; HEAP_ZERO_MEMORY zeroes beyond the old request */
    uint8_t *pa = guest_ptr(&m, a, 1, GUEST_PERM_W);
    pa[0] = 0x77;
    uint64_t a2 = guest_heap_realloc(&h, a, 5000, 1);
    CHECK(a2 != 0);
    uint8_t *p2 = guest_ptr(&m, a2, 5000, GUEST_PERM_R);
    EQ(p2[0], 0x77);
    zero = 1; for (int i = 1; i < 5000; i++) zero &= p2[i] == 0;
    CHECK(zero);
    /* shrink in place keeps the address */
    EQ(guest_heap_realloc(&h, a2, 10, 0), a2);
    EQ(guest_heap_block_size(&h, a2), 16);
    /* in-place growth within the block zeroes [old request, new request) */
    p2 = guest_ptr(&m, a2, 16, GUEST_PERM_W);
    memset(p2 + 10, 0xee, 6);
    EQ(guest_heap_realloc(&h, a2, 16, 1), a2);
    EQ(p2[9], 0); EQ(p2[10], 0); EQ(p2[15], 0);
    /* exhaustion fails cleanly and keeps the old block */
    EQ(guest_heap_alloc(&h, SIZE, 0), 0);
    EQ(guest_heap_realloc(&h, a2, SIZE, 0), 0);
    EQ(guest_heap_block_size(&h, a2), 16);
    EQ(guest_heap_alloc(&h, ~0ull, 0), 0);                 /* size overflow */
    invariants();
    guest_heap_destroy(&h, &m);
}

static uint64_t rng = 88172645463325252ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static void test_stress(void) {
    memset(&m, 0, sizeof m);
    CHECK(guest_heap_init(&h, &m, BASE, SIZE) == 0);
    uint64_t live[64] = {0}, lsize[64] = {0};
    for (int it = 0; it < 20000; it++) {
        unsigned k = (unsigned)(rnd() % 64);
        if (live[k]) {
            /* contents survive until free: check the stamp */
            uint8_t *p = guest_ptr(&m, live[k], lsize[k], GUEST_PERM_R);
            CHECK(p[0] == (uint8_t)k && p[lsize[k] - 1] == (uint8_t)k);
            if (rnd() & 1) { CHECK(guest_heap_free(&h, live[k])); live[k] = 0; }
            else {
                uint64_t ns = 1 + rnd() % 900;
                uint64_t nv = guest_heap_realloc(&h, live[k], ns, 0);
                if (nv) {
                    uint8_t *q = guest_ptr(&m, nv, ns, GUEST_PERM_W);
                    CHECK(q[0] == (uint8_t)k);
                    memset(q, (int)k, ns);
                    live[k] = nv; lsize[k] = ns;
                }
            }
        } else {
            uint64_t sz = 1 + rnd() % 900;
            uint64_t v = guest_heap_alloc(&h, sz, 0);
            if (v) { memset(guest_ptr(&m, v, sz, GUEST_PERM_W), (int)k, sz); live[k] = v; lsize[k] = sz; }
        }
    }
    invariants();
    for (unsigned k = 0; k < 64; k++) if (live[k]) CHECK(guest_heap_free(&h, live[k]));
    EQ(h.n, 1);                                            /* everything coalesced back */
    guest_heap_destroy(&h, &m);
}

static void quoted(const char *arg, const char *expect) {
    char buf[256];
    uint64_t n = exe2mac_quote_arg(arg, buf, sizeof buf);
    buf[n] = 0;
    checks++;
    if (strcmp(buf, expect)) { failures++; fprintf(stderr, "quote(%s) = %s, expected %s\n", arg, buf, expect); }
    EQ(exe2mac_quote_arg(arg, NULL, 0), n);                /* length-only mode agrees */
}

static void test_quoting(void) {
    quoted("plain", "plain");
    quoted("", "\"\"");
    quoted("b c", "\"b c\"");
    quoted("a\tb", "\"a\tb\"");
    quoted("q\"uote", "\"q\\\"uote\"");
    quoted("back\\slash\\", "back\\slash\\");             /* no quoting needed: backslashes literal */
    quoted("sp ace\\", "\"sp ace\\\\\"");                 /* trailing backslash doubled before quote */
    quoted("a\\\"b", "\"a\\\\\\\"b\"");                   /* a\"b -> "a\\\"b" */
    quoted("c:\\dir name\\", "\"c:\\dir name\\\\\"");
}

int main(void) {
    test_basic();
    test_stress();
    test_quoting();
    printf("checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
