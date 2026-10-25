/* Deterministic, portable unit tests for runtime/x86_cpu.h and guest_mem.
 * Expected values are written from the Intel SDM definitions, not from the
 * implementation. Runs on any host (x86-64 or ARM64). */
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "runtime/x86_cpu.h"

static int failures, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); checks++; if (_a != _b) { failures++; \
    fprintf(stderr, "%s:%d: %s == 0x%" PRIx64 ", expected 0x%" PRIx64 "\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)
#define FLAGS(s, c, p, a, z, sg, o) do { EQ((s)->cf, c); EQ((s)->pf, p); EQ((s)->af, a); \
    EQ((s)->zf, z); EQ((s)->sf, sg); EQ((s)->of, o); } while (0)

static x86_state fresh(void) {
    x86_state s;
    memset(&s, 0, sizeof s);
    return s;
}

/* Run fn in a child; return its exit status (or -signal). */
static int child_status(void (*fn)(void)) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, 2);
        fn();
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st);
}

static void test_registers(void) {
    x86_state s = fresh();
    s.gpr[X86_RAX] = 0x1122334455667788ull;
    x86_set(&s, X86_RAX, 32, 0, 0xdeadbeef);
    EQ(s.gpr[X86_RAX], 0x00000000deadbeefull);            /* 32-bit write zero-extends */
    s.gpr[X86_RAX] = 0x1122334455667788ull;
    x86_set(&s, X86_RAX, 16, 0, 0xabcd);
    EQ(s.gpr[X86_RAX], 0x112233445566abcdull);            /* 16-bit merges */
    x86_set(&s, X86_RAX, 8, 0, 0x1ff);
    EQ(s.gpr[X86_RAX], 0x112233445566abffull);            /* 8-bit low merges, value masked */
    x86_set(&s, X86_RAX, 8, 1, 0x42);
    EQ(s.gpr[X86_RAX], 0x11223344556642ffull);            /* AH */
    EQ(x86_get(&s, X86_RAX, 8, 1), 0x42);
    EQ(x86_get(&s, X86_RAX, 16, 0), 0x42ff);
    EQ(x86_get(&s, X86_RAX, 32, 0), 0x556642ff);
    x86_set(&s, X86_R11, 8, 0, 0x30);
    EQ(s.gpr[X86_R11], 0x30);
    x86_set(&s, X86_R8, 64, 0, ~0ull);
    EQ(s.gpr[X86_R8], ~0ull);
    EQ(x86_sext(0x80, 8), 0xffffffffffffff80ull);
    EQ(x86_sext(0x7f, 8), 0x7f);
    EQ(x86_sext(0xfffffffc, 32), 0xfffffffffffffffcull);
    EQ(x86_sext(0x123456789ull, 32), 0x23456789ull);
    EQ(x86_sext(0x8000000000000000ull, 64), 0x8000000000000000ull);
    EQ(x86_parity8(0x00), 1);
    EQ(x86_parity8(0x01), 0);
    EQ(x86_parity8(0x03), 1);
}

static void test_parity_low_byte_only(void) {
    /* PF uses only bits 0..7: 0x1ff -> low byte 0xff (8 set bits, even) -> 1 */
    EQ(x86_parity8(0xff), 1);
    EQ(x86_parity8(0x100), 1);
    EQ(x86_parity8(0x107), 0);
}

static void test_add_sub(void) {
    x86_state s = fresh();
    EQ(x86_add(&s, 0x7f, 1, 8), 0x80);         FLAGS(&s, 0, 0, 1, 0, 1, 1);
    EQ(x86_add(&s, 0xff, 1, 8), 0x00);         FLAGS(&s, 1, 1, 1, 1, 0, 0);
    EQ(x86_add(&s, 0x80, 0x80, 8), 0x00);      FLAGS(&s, 1, 1, 0, 1, 0, 1);
    EQ(x86_add(&s, ~0ull, 1, 64), 0);          FLAGS(&s, 1, 1, 1, 1, 0, 0);
    EQ(x86_add(&s, 0x7fffffffffffffffull, 1, 64), 0x8000000000000000ull); FLAGS(&s, 0, 1, 1, 0, 1, 1);
    EQ(x86_add(&s, 0xffffffff, 0, 32), 0xffffffff); FLAGS(&s, 0, 1, 0, 0, 1, 0);
    /* add rsi, -2 : 5 + (-2) */
    EQ(x86_add(&s, 5, 0xfffffffffffffffeull, 64), 3); FLAGS(&s, 1, 1, 1, 0, 0, 0);

    EQ(x86_sub(&s, 0, 1, 32), 0xffffffff);     FLAGS(&s, 1, 1, 1, 0, 1, 0);
    EQ(x86_sub(&s, 0x80, 1, 8), 0x7f);         FLAGS(&s, 0, 0, 1, 0, 0, 1);
    EQ(x86_sub(&s, 5, 5, 64), 0);              FLAGS(&s, 0, 1, 0, 1, 0, 0);
    EQ(x86_sub(&s, 0x10, 1, 16), 0x0f);        FLAGS(&s, 0, 1, 1, 0, 0, 0);
    /* cmp edi, 0x11 with edi = 0x10, 0x11, 0x14 (fib loop bound) */
    x86_sub(&s, 0x10, 0x11, 32); CHECK(x86_cond(&s, X86_CC_B));
    x86_sub(&s, 0x11, 0x11, 32); CHECK(!x86_cond(&s, X86_CC_B));
    x86_sub(&s, 0x14, 0x11, 32); CHECK(!x86_cond(&s, X86_CC_B));
    /* signed compare: -7 vs 3 (32-bit) */
    x86_sub(&s, 0xfffffff9, 3, 32); CHECK(x86_cond(&s, X86_CC_LE)); CHECK(!x86_cond(&s, X86_CC_G));
    x86_sub(&s, 3, 0xfffffff9, 32); CHECK(x86_cond(&s, X86_CC_G)); CHECK(x86_cond(&s, X86_CC_B));
}

static void test_logic(void) {
    x86_state s = fresh();
    s.cf = s.of = 1; s.af = 1;
    EQ(x86_xor(&s, 0x1234, 0x1234, 32), 0);    EQ(s.cf, 0); EQ(s.of, 0); EQ(s.zf, 1); EQ(s.sf, 0); EQ(s.pf, 1);
    EQ(s.af, 1);                                /* AF undefined -> left unchanged */
    EQ(x86_or(&s, 0x05, 0x30, 8), 0x35);       EQ(s.zf, 0); EQ(s.sf, 0); EQ(s.pf, 1);
    EQ(x86_and(&s, 0x8000000000000000ull, ~0ull, 64), 0x8000000000000000ull); EQ(s.sf, 1);
    x86_and(&s, 0xfffffffc, 0xfffffffc, 32);   CHECK(x86_cond(&s, X86_CC_S)); CHECK(!x86_cond(&s, X86_CC_NS));
}

static void test_inc_dec_neg(void) {
    x86_state s = fresh();
    s.cf = 1;
    EQ(x86_inc(&s, 0x7fffffff, 32), 0x80000000); EQ(s.cf, 1); EQ(s.of, 1); EQ(s.sf, 1); EQ(s.af, 1);
    s.cf = 0;
    EQ(x86_inc(&s, ~0ull, 64), 0);              EQ(s.cf, 0); EQ(s.zf, 1); EQ(s.of, 0);
    s.cf = 1;
    EQ(x86_dec(&s, 0, 32), 0xffffffff);         EQ(s.cf, 1); EQ(s.sf, 1); EQ(s.of, 0); EQ(s.af, 1);
    EQ(x86_dec(&s, 0x80000000, 32), 0x7fffffff); EQ(s.of, 1);
    EQ(x86_dec(&s, 1, 64), 0);                  EQ(s.zf, 1);

    EQ(x86_neg(&s, 0, 64), 0);                  EQ(s.cf, 0); EQ(s.zf, 1); EQ(s.of, 0);
    EQ(x86_neg(&s, 5, 64), 0xfffffffffffffffbull); EQ(s.cf, 1); EQ(s.sf, 1); EQ(s.of, 0);
    EQ(x86_neg(&s, 0x80000000, 32), 0x80000000); EQ(s.cf, 1); EQ(s.of, 1); EQ(s.sf, 1);
    EQ(x86_neg(&s, 0xfffffffc, 32), 4);         EQ(s.sf, 0); EQ(s.cf, 1);
    /* neg/cmovs = abs: neg sets SF from the negated value */
    x86_neg(&s, 0x15, 32);                       CHECK(x86_cond(&s, X86_CC_S));
}

static void test_shr(void) {
    x86_state s = fresh();
    s.cf = 1; s.zf = 1; s.of = 1;
    EQ(x86_shr(&s, 0x1234, 0, 64), 0x1234);     EQ(s.cf, 1); EQ(s.zf, 1); EQ(s.of, 1);   /* count 0: flags unchanged */
    EQ(x86_shr(&s, 0x1234, 64, 64), 0x1234);    EQ(s.cf, 1);                              /* count masked to 0 */
    EQ(x86_shr(&s, 0x8000000000000001ull, 1, 64), 0x4000000000000000ull); EQ(s.cf, 1); EQ(s.of, 1);
    EQ(x86_shr(&s, 0x0c, 3, 64), 1);             EQ(s.cf, 1); EQ(s.zf, 0);
    EQ(x86_shr(&s, 0x04, 3, 64), 0);             EQ(s.cf, 1); EQ(s.zf, 1);
    EQ(x86_shr(&s, 0x80000000, 33, 32), 0x40000000); EQ(s.cf, 0);   /* 32-bit: count & 0x1f = 1 */
    EQ(x86_shr(&s, 0x80, 1, 8), 0x40);           EQ(s.of, 1);
}

static void test_mul_imul(void) {
    x86_state s = fresh();
    /* div-by-10 reciprocal used by print_num: 1234 * 0xcccccccccccccccd >> 64 >> 3 == 123 */
    s.gpr[X86_RAX] = 1234;
    x86_mul(&s, 0xcccccccccccccccdull, 64);
    EQ(s.gpr[X86_RDX] >> 3, 123);
    EQ(s.gpr[X86_RAX], (uint64_t)(1234ull * 0xcccccccccccccccdull));
    EQ(s.cf, 1); EQ(s.of, 1);
    s.gpr[X86_RAX] = 7; s.gpr[X86_RDX] = 0xdead;
    x86_mul(&s, 6, 64);
    EQ(s.gpr[X86_RAX], 42); EQ(s.gpr[X86_RDX], 0); EQ(s.cf, 0); EQ(s.of, 0);
    s.gpr[X86_RAX] = 0xffffffff00000002ull; s.gpr[X86_RDX] = ~0ull;
    x86_mul(&s, 0x80000000, 32);
    EQ(s.gpr[X86_RAX], 0); EQ(s.gpr[X86_RDX], 1); EQ(s.cf, 1);

    EQ(x86_imul2(&s, 84, 0xfffffffc, 32), (uint32_t)-336); EQ(s.cf, 0); EQ(s.of, 0);
    EQ(x86_imul2(&s, 0x40000000, 4, 32), 0);   EQ(s.cf, 1); EQ(s.of, 1);
    EQ(x86_imul2(&s, 0xffffffff, 0xffffffff, 32), 1); EQ(s.of, 0);
    EQ(x86_imul2(&s, 0x4000000000000000ull, 2, 64), 0x8000000000000000ull); EQ(s.of, 1);
    EQ(x86_imul2(&s, ~0ull, 0x8000000000000000ull, 64), 0x8000000000000000ull); EQ(s.of, 1);
    EQ(x86_imul2(&s, ~0ull, 0x7fffffffffffffffull, 64), 0x8000000000000001ull); EQ(s.of, 0);
}

static void test_idiv_cdq(void) {
    x86_state s = fresh();
    s.gpr[X86_RAX] = 0xffffffff00000054ull;     /* garbage upper bits must be ignored */
    x86_cdq(&s);                                 EQ(s.gpr[X86_RDX], 0);
    x86_idiv(&s, 0xfffffffc, 32);               EQ(s.gpr[X86_RAX], (uint32_t)-21); EQ(s.gpr[X86_RDX], 0);
    s.gpr[X86_RAX] = (uint32_t)-7;
    x86_cdq(&s);                                 EQ(s.gpr[X86_RDX], 0xffffffff);
    x86_idiv(&s, 2, 32);                         EQ(s.gpr[X86_RAX], (uint32_t)-3); EQ(s.gpr[X86_RDX], (uint32_t)-1);
    s.gpr[X86_RAX] = 7; x86_cdq(&s);
    x86_idiv(&s, (uint32_t)-2, 32);              EQ(s.gpr[X86_RAX], (uint32_t)-3); EQ(s.gpr[X86_RDX], 1);
    s.gpr[X86_RAX] = 0x8000000000000000ull; x86_cqo(&s); EQ(s.gpr[X86_RDX], ~0ull);
    x86_idiv(&s, 2, 64);                         EQ(s.gpr[X86_RAX], 0xc000000000000000ull); EQ(s.gpr[X86_RDX], 0);
}

static void div_zero(void) { x86_state s = fresh(); s.gpr[X86_RAX] = 1; x86_idiv(&s, 0, 32); }
static void div_overflow32(void) {
    x86_state s = fresh(); s.gpr[X86_RAX] = 0x80000000u; x86_cdq(&s); x86_idiv(&s, 0xffffffff, 32);
}
static void div_overflow32_wide(void) {      /* EDX:EAX too large for a 32-bit quotient */
    x86_state s = fresh(); s.gpr[X86_RAX] = 0; s.gpr[X86_RDX] = 1; x86_idiv(&s, 1, 32);
}
static void div_overflow64(void) {
    x86_state s = fresh(); s.gpr[X86_RAX] = 0x8000000000000000ull; x86_cqo(&s); x86_idiv(&s, ~0ull, 64);
}

static void test_div_faults(void) {
    EQ(child_status(div_zero), 0x94);           /* STATUS_INTEGER_DIVIDE_BY_ZERO & 0xff */
    EQ(child_status(div_overflow32), 0x95);     /* STATUS_INTEGER_OVERFLOW & 0xff */
    EQ(child_status(div_overflow32_wide), 0x95);
    EQ(child_status(div_overflow64), 0x95);
}

static void test_conditions(void) {
    /* exhaustive over all 64 combinations of CF, ZF, SF, OF, PF (+AF ignored) */
    for (unsigned bits = 0; bits < 32; bits++) {
        x86_state s = fresh();
        s.cf = bits & 1; s.zf = (bits >> 1) & 1; s.sf = (bits >> 2) & 1; s.of = (bits >> 3) & 1; s.pf = (bits >> 4) & 1;
        int expect[16] = {
            s.of, !s.of, s.cf, !s.cf, s.zf, !s.zf, s.cf || s.zf, !s.cf && !s.zf,
            s.sf, !s.sf, s.pf, !s.pf, s.sf != s.of, s.sf == s.of,
            s.zf || (s.sf != s.of), !s.zf && (s.sf == s.of),
        };
        for (int cc = 0; cc < 16; cc++) EQ(!!x86_cond(&s, cc), expect[cc]);
    }
}

static uint8_t img[0x100], stack_mem[0x100];
static guest_mem mem;

static void setup_mem(void) {
    memset(&mem, 0, sizeof mem);
    memset(img, 0, sizeof img);
    memset(stack_mem, 0, sizeof stack_mem);
    CHECK(guest_map(&mem, 0x140000000ull, sizeof img, img, GUEST_PERM_R, "image") == 0);
    CHECK(guest_map(&mem, 0x10000, sizeof stack_mem, stack_mem, GUEST_PERM_R | GUEST_PERM_W, "stack") == 0);
}

static void oob_read(void) { setup_mem(); guest_ld64(&mem, 0x10000 + 0xf9); }
static void ro_write(void) { setup_mem(); guest_st8(&mem, 0x140000000ull, 1); }
static void unmapped(void) { setup_mem(); guest_ld8(&mem, 0); }
static void wrap(void) { setup_mem(); guest_ld64(&mem, ~0ull - 3); }
static void stack_underflow(void) {
    setup_mem(); x86_state s = fresh(); s.mem = &mem; s.gpr[X86_RSP] = 0x10000; x86_push64(&s, 1);
}

static void test_memory(void) {
    setup_mem();
    CHECK(guest_map(&mem, 0x100f0, 0x20, stack_mem, GUEST_PERM_R, "overlap") == -1);
    CHECK(guest_map(&mem, ~0ull - 1, 4, stack_mem, GUEST_PERM_R, "wraps") == -1);
    guest_st64(&mem, 0x10010, 0x1122334455667788ull);
    EQ(stack_mem[0x10], 0x88); EQ(stack_mem[0x17], 0x11);          /* little-endian */
    EQ(guest_ld32(&mem, 0x10010), 0x55667788);
    EQ(guest_ld16(&mem, 0x10013), 0x4455);                          /* unaligned */
    EQ(guest_ld8(&mem, 0x10017), 0x11);
    guest_st16(&mem, 0x1004d, 0x342d);
    EQ(stack_mem[0x4d], 0x2d); EQ(stack_mem[0x4e], 0x34);
    EQ(guest_ld64(&mem, 0x10000 + 0xf8), 0);                        /* last 8 bytes OK */
    CHECK(guest_try_ptr(&mem, 0x10000 + 0xf9, 8, GUEST_PERM_R) == NULL);
    CHECK(guest_try_ptr(&mem, 0x140000000ull, 1, GUEST_PERM_W) == NULL);
    CHECK(guest_try_ptr(&mem, 0x140000000ull, 0x100, GUEST_PERM_R) == img);
    CHECK(guest_try_ptr(&mem, 0x140000000ull, 0x101, GUEST_PERM_R) == NULL);

    x86_state s = fresh();
    s.mem = &mem;
    s.gpr[X86_RSP] = 0x10100;
    x86_push64(&s, 0xaabbccddeeff0011ull);
    EQ(s.gpr[X86_RSP], 0x100f8);
    x86_push64(&s, 2);
    EQ(x86_pop64(&s), 2);
    EQ(x86_pop64(&s), 0xaabbccddeeff0011ull);
    EQ(s.gpr[X86_RSP], 0x10100);

    EQ(child_status(oob_read), 0x05);           /* STATUS_ACCESS_VIOLATION & 0xff */
    EQ(child_status(ro_write), 0x05);
    EQ(child_status(unmapped), 0x05);
    EQ(child_status(wrap), 0x05);
    EQ(child_status(stack_underflow), 0x05);
}

static void test_adc_sbb_not(void) {
    x86_state s = fresh();
    /* 128-bit add: low halves carry into the high halves */
    uint64_t lo = x86_add(&s, ~0ull, 1, 64);            EQ(lo, 0); EQ(s.cf, 1);
    EQ(x86_adc(&s, 5, 7, 64), 13);                        EQ(s.cf, 0);
    s.cf = 1; EQ(x86_adc(&s, ~0ull, 0, 64), 0);           EQ(s.cf, 1); EQ(s.zf, 1);
    s.cf = 1; EQ(x86_adc(&s, ~0ull, ~0ull, 64), ~0ull);   EQ(s.cf, 1); EQ(s.sf, 1);
    s.cf = 1; EQ(x86_adc(&s, 0x7f, 0, 8), 0x80);          EQ(s.of, 1); EQ(s.af, 1);
    /* 128-bit subtract */
    lo = x86_sub(&s, 0, 1, 64);                           EQ(lo, ~0ull); EQ(s.cf, 1);
    EQ(x86_sbb(&s, 10, 3, 64), 6);                        EQ(s.cf, 0);
    s.cf = 1; EQ(x86_sbb(&s, 5, 5, 64), ~0ull);           EQ(s.cf, 1); EQ(s.sf, 1);
    s.cf = 1; EQ(x86_sbb(&s, 0, ~0ull, 64), 0);           EQ(s.cf, 1); EQ(s.zf, 1);
    s.cf = 0; EQ(x86_sbb(&s, 0x80, 1, 8), 0x7f);          EQ(s.of, 1);
    s.cf = 1; s.zf = 1;
    EQ(x86_not(0x00ff00ff00ff00ffull, 64), 0xff00ff00ff00ff00ull); EQ(s.cf, 1); EQ(s.zf, 1);
    EQ(x86_not(0x12, 8), 0xed);
}

static void test_shl_sar(void) {
    x86_state s = fresh();
    s.cf = 1; s.of = 1; s.zf = 1;
    EQ(x86_shl(&s, 0x1234, 0, 64), 0x1234);   EQ(s.cf, 1); EQ(s.of, 1); EQ(s.zf, 1);
    EQ(x86_shl(&s, 0x8000000000000001ull, 1, 64), 2);  EQ(s.cf, 1); EQ(s.of, 1);  /* MSB(r)=0 ^ CF=1 */
    EQ(x86_shl(&s, 0x4000000000000000ull, 1, 64), 0x8000000000000000ull); EQ(s.cf, 0); EQ(s.of, 1); EQ(s.sf, 1);
    EQ(x86_shl(&s, 0x8000000000000001ull, 63, 64), 0x8000000000000000ull); EQ(s.cf, 0);
    EQ(x86_shl(&s, 0x8000000000000001ull, 64, 64), 0x8000000000000001ull);  /* count & 63 == 0 */
    EQ(x86_shl(&s, 0x81, 1, 8), 0x02);         EQ(s.cf, 1);
    EQ(x86_shl(&s, 0x01, 8, 8), 0x00);         EQ(s.cf, 1); EQ(s.zf, 1);    /* last bit out is bit 0 */
    EQ(x86_shl(&s, 0xdeadbeef, 33, 32), 0xbd5b7dde); EQ(s.cf, 1);           /* count & 31 == 1 */

    EQ(x86_sar(&s, 0xfffffff16bab0000ull, 0, 64), 0xfffffff16bab0000ull);
    EQ(x86_sar(&s, (uint64_t)-1000000000000LL, 1, 64), (uint64_t)-500000000000LL); EQ(s.of, 0); EQ(s.cf, 0);
    EQ(x86_sar(&s, (uint64_t)-1000000000000LL, 63, 64), ~0ull); EQ(s.cf, 1);
    EQ(x86_sar(&s, (uint64_t)-1LL, 7, 64), ~0ull);  EQ(s.cf, 1);
    EQ(x86_sar(&s, (uint64_t)-7LL, 1, 64), (uint64_t)-4LL); EQ(s.cf, 1);       /* rounds toward -inf */
    EQ(x86_sar(&s, 0x7fffffffffffffffull, 62, 64), 1); EQ(s.cf, 1); EQ(s.sf, 0);
    EQ(x86_sar(&s, 0x80, 1, 8), 0xc0);          EQ(s.sf, 1); EQ(s.cf, 0);
    EQ(x86_sar(&s, 0x80, 20, 8), 0xff);         /* 8-bit, count 20 < 32: all sign bits */
    EQ(x86_sar(&s, 0x80000000, 31, 32), 0xffffffff);
}

static void test_div(void) {
    x86_state s = fresh();
    s.gpr[X86_RAX] = 1000000007; s.gpr[X86_RDX] = 0;
    x86_div(&s, 10, 64);                         EQ(s.gpr[X86_RAX], 100000000); EQ(s.gpr[X86_RDX], 7);
    s.gpr[X86_RAX] = ~0ull; s.gpr[X86_RDX] = 0;
    x86_div(&s, 3, 64);                          EQ(s.gpr[X86_RAX], 0x5555555555555555ull); EQ(s.gpr[X86_RDX], 0);
    s.gpr[X86_RAX] = 0; s.gpr[X86_RDX] = 1;      /* 2^64 / 2 */
    x86_div(&s, 2, 64);                          EQ(s.gpr[X86_RAX], 0x8000000000000000ull); EQ(s.gpr[X86_RDX], 0);
    s.gpr[X86_RAX] = 0xffffffff00000007ull; s.gpr[X86_RDX] = 0xabcdabcd00000000ull;  /* upper halves ignored */
    x86_div(&s, 0x100000002ull, 32);             EQ(s.gpr[X86_RAX], 3); EQ(s.gpr[X86_RDX], 1);
}
static void udiv_zero(void) { x86_state s = fresh(); s.gpr[X86_RAX] = 5; x86_div(&s, 0, 64); }
static void udiv_overflow(void) { x86_state s = fresh(); s.gpr[X86_RDX] = 3; x86_div(&s, 3, 64); }
static void udiv_overflow32(void) { x86_state s = fresh(); s.gpr[X86_RDX] = 1; x86_div(&s, 1, 32); }

static uint8_t sbuf[0x40];
static guest_mem smem;
static x86_state string_state(void) {
    memset(&smem, 0, sizeof smem);
    memset(sbuf, 0, sizeof sbuf);
    guest_map(&smem, 0x5000, sizeof sbuf, sbuf, GUEST_PERM_R | GUEST_PERM_W, "buf");
    x86_state s = fresh();
    s.mem = &smem;
    return s;
}

static void test_string_ops(void) {
    x86_state s = string_state();
    s.gpr[X86_RAX] = 0x1234; s.gpr[X86_RDI] = 0x5004; s.gpr[X86_RCX] = 8;
    s.zf = 1; s.cf = 1;
    x86_rep_stosb(&s);
    EQ(s.gpr[X86_RCX], 0); EQ(s.gpr[X86_RDI], 0x500c); EQ(s.zf, 1); EQ(s.cf, 1);
    EQ(sbuf[3], 0); EQ(sbuf[4], 0x34); EQ(sbuf[11], 0x34); EQ(sbuf[12], 0);
    /* RCX == 0: nothing happens, no memory touched */
    s.gpr[X86_RDI] = 0xdead0000; x86_rep_stosb(&s); EQ(s.gpr[X86_RDI], 0xdead0000);
    /* overlapping forward copy replicates the first byte, exactly like hardware */
    for (int i = 0; i < 8; i++) sbuf[0x20 + i] = (uint8_t)('a' + i);
    s.gpr[X86_RSI] = 0x5020; s.gpr[X86_RDI] = 0x5021; s.gpr[X86_RCX] = 4;
    x86_rep_movsb(&s);
    EQ(sbuf[0x21], 'a'); EQ(sbuf[0x24], 'a'); EQ(sbuf[0x25], 'f');
    EQ(s.gpr[X86_RSI], 0x5024); EQ(s.gpr[X86_RDI], 0x5025); EQ(s.gpr[X86_RCX], 0);
    /* DF=1 copies backwards */
    s.df = 1; s.gpr[X86_RSI] = 0x5003; s.gpr[X86_RDI] = 0x5013; s.gpr[X86_RCX] = 2;
    sbuf[2] = 0x77; sbuf[3] = 0x88;
    x86_rep_movsb(&s);
    EQ(sbuf[0x13], 0x88); EQ(sbuf[0x12], 0x77); EQ(s.gpr[X86_RDI], 0x5011);
}
static void stos_oob(void) {
    x86_state s = string_state(); s.gpr[X86_RDI] = 0x5000 + 0x3e; s.gpr[X86_RCX] = 4; x86_rep_stosb(&s);
}

static void test_movaps(void) {
    x86_state s = string_state();
    for (int i = 0; i < 16; i++) sbuf[i] = (uint8_t)(0xa0 + i);
    x86_ld128(&s, 3, 0x5000, 1);
    EQ(s.xmm[3].lo, 0xa7a6a5a4a3a2a1a0ull); EQ(s.xmm[3].hi, 0xafaeadacabaaa9a8ull);
    x86_st128(&s, 3, 0x5010, 1);
    CHECK(memcmp(sbuf, sbuf + 0x10, 16) == 0);
    x86_ld128(&s, 4, 0x5001, 0);                 /* unaligned allowed when not required */
    EQ(s.xmm[4].lo & 0xff, 0xa1);
}
static void movaps_misaligned(void) { x86_state s = string_state(); x86_ld128(&s, 0, 0x5008, 1); }
static void movaps_partial_oob(void) { x86_state s = string_state(); x86_st128(&s, 0, 0x5030 + 0x10 - 8, 0); }

static void test_cdqe_cwde(void) {
    x86_state s = fresh();
    s.gpr[X86_RAX] = 0x12345678fffffff9ull; x86_cdqe(&s); EQ(s.gpr[X86_RAX], 0xfffffffffffffff9ull);
    s.gpr[X86_RAX] = 0xffffffff7fffffffull; x86_cdqe(&s); EQ(s.gpr[X86_RAX], 0x7fffffffull);
    s.gpr[X86_RAX] = 0x123456789abc8001ull; x86_cwde(&s); EQ(s.gpr[X86_RAX], 0xffff8001ull);
    s.gpr[X86_RAX] = 0xffffffffffff7fffull; x86_cwde(&s); EQ(s.gpr[X86_RAX], 0x7fffull);
}

static void test_bt(void) {
    x86_state s = fresh();
    s.zf = 1;
    x86_bt(&s, 0x100002600ull, 9, 64);   EQ(s.cf, 1); EQ(s.zf, 1);
    x86_bt(&s, 0x100002600ull, 8, 64);   EQ(s.cf, 0);
    x86_bt(&s, 0x100002600ull, 32, 64);  EQ(s.cf, 1);
    x86_bt(&s, 0x100002600ull, 96, 64);  EQ(s.cf, 1);    /* 96 & 63 == 32 */
    x86_bt(&s, 0x80000000u, 63, 32);     EQ(s.cf, 1);    /* 63 & 31 == 31 */
    x86_bt(&s, 0x8000u, 31, 16);         EQ(s.cf, 1);    /* 31 & 15 == 15 */
}

static void test_new_faults(void) {
    EQ(child_status(udiv_zero), 0x94);
    EQ(child_status(udiv_overflow), 0x95);
    EQ(child_status(udiv_overflow32), 0x95);
    EQ(child_status(stos_oob), 0x05);
    EQ(child_status(movaps_misaligned), 0x05);
    EQ(child_status(movaps_partial_oob), 0x05);
}

int main(void) {
    test_registers();
    test_parity_low_byte_only();
    test_add_sub();
    test_logic();
    test_inc_dec_neg();
    test_shr();
    test_mul_imul();
    test_idiv_cdq();
    test_div_faults();
    test_conditions();
    test_memory();
    test_adc_sbb_not();
    test_shl_sar();
    test_div();
    test_string_ops();
    test_movaps();
    test_bt();
    test_cdqe_cwde();
    test_new_faults();
    printf("checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
