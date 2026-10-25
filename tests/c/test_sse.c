/* Portable unit tests for runtime/x86_sse.h. Expected bit patterns come from
 * the Intel SDM rules, not from the implementation. They run on ARM64 too,
 * where host NaN handling and out-of-range float->int conversions differ
 * from x86 - exactly the cases checked here. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include "runtime/x86_sse.h"

static int failures, checks;
#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); checks++; if (_a != _b) { failures++; \
    fprintf(stderr, "%s:%d: %s == 0x%016" PRIx64 ", expected 0x%016" PRIx64 "\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)

#define ONE   0x3FF0000000000000ull
#define TWO   0x4000000000000000ull
#define MONE  0xBFF0000000000000ull
#define PZERO 0x0000000000000000ull
#define NZERO 0x8000000000000000ull
#define PINF  0x7FF0000000000000ull
#define NINF  0xFFF0000000000000ull
#define QNAN1 0x7FF8000000000123ull
#define QNAN2 0xFFF800000000ABCDull
#define SNAN1 0x7FF0000000000001ull
#define DMIN  0x0000000000000001ull       /* smallest denormal */

static void test_nan_rules(void) {
    /* invalid operations produce the NEGATIVE QNaN indefinite on x86 */
    EQ(sse_f64_arith(PZERO, PZERO, SSE_DIV), 0xFFF8000000000000ull);
    EQ(sse_f64_arith(PINF, PINF, SSE_SUB), 0xFFF8000000000000ull);
    EQ(sse_f64_arith(PINF, PZERO, SSE_MUL), 0xFFF8000000000000ull);
    EQ(sse_f64_arith(NINF, PINF, SSE_ADD), 0xFFF8000000000000ull);
    EQ(sse_f64_sqrt(MONE), 0xFFF8000000000000ull);
    EQ(sse_f32_arith(0, 0, SSE_DIV), 0xFFC00000u);
    /* propagation: first operand wins, payload and sign kept, quiet bit set */
    EQ(sse_f64_arith(QNAN1, QNAN2, SSE_ADD), QNAN1);
    EQ(sse_f64_arith(QNAN2, QNAN1, SSE_MUL), QNAN2);
    EQ(sse_f64_arith(ONE, QNAN2, SSE_SUB), QNAN2);
    EQ(sse_f64_arith(SNAN1, ONE, SSE_ADD), SNAN1 | F64_QUIET_BIT);
    EQ(sse_f64_arith(ONE, SNAN1, SSE_DIV), SNAN1 | F64_QUIET_BIT);
    EQ(sse_f64_arith(SNAN1, QNAN2, SSE_ADD), SNAN1 | F64_QUIET_BIT);
    EQ(sse_f64_sqrt(QNAN2), QNAN2);
    EQ(sse_f32_arith(0x7F800001u, 0x3F800000u, SSE_ADD), 0x7FC00001u);
}

static void test_ieee_cases(void) {
    EQ(sse_f64_arith(ONE, ONE, SSE_ADD), TWO);
    EQ(sse_f64_arith(0x3FB999999999999Aull, 0x3FC999999999999Aull, SSE_ADD), 0x3FD3333333333334ull); /* 0.1+0.2 */
    EQ(sse_f64_arith(ONE, ONE, SSE_SUB), PZERO);                  /* x - x = +0 in RN */
    EQ(sse_f64_arith(NZERO, NZERO, SSE_ADD), NZERO);
    EQ(sse_f64_arith(NZERO, PZERO, SSE_ADD), PZERO);
    EQ(sse_f64_arith(ONE, PZERO, SSE_DIV), PINF);
    EQ(sse_f64_arith(MONE, PZERO, SSE_DIV), NINF);
    EQ(sse_f64_arith(0x7FEFFFFFFFFFFFFFull, TWO, SSE_MUL), PINF); /* overflow */
    EQ(sse_f64_arith(DMIN, 0x3FE0000000000000ull, SSE_MUL), PZERO);  /* denormal * 0.5 -> ties-to-even 0 */
    EQ(sse_f64_arith(0x0010000000000000ull, TWO, SSE_DIV), 0x0008000000000000ull);  /* gradual underflow, no FTZ */
    EQ(sse_f64_sqrt(NZERO), NZERO);
    EQ(sse_f64_sqrt(0x4010000000000000ull), TWO);                  /* sqrt(4) */
    EQ(sse_f64_sqrt(PINF), PINF);
}

static void test_min_max(void) {
    EQ(sse_f64_max(ONE, TWO), TWO);
    EQ(sse_f64_min(ONE, TWO), ONE);
    EQ(sse_f64_max(PZERO, NZERO), NZERO);    /* equal -> second operand */
    EQ(sse_f64_max(NZERO, PZERO), PZERO);
    EQ(sse_f64_min(PZERO, NZERO), NZERO);
    EQ(sse_f64_max(QNAN1, ONE), ONE);        /* any NaN -> second operand, unchanged */
    EQ(sse_f64_max(ONE, SNAN1), SNAN1);      /* not quieted */
    EQ(sse_f64_min(QNAN1, QNAN2), QNAN2);
}

static uint64_t flags_of(const x86_state *s) {
    return (uint64_t)s->zf << 2 | (uint64_t)s->pf << 1 | s->cf;
}

static void test_compare(void) {
    x86_state s; memset(&s, 0, sizeof s);
    s.of = s.sf = s.af = 1;
    sse_f64_ucomi(&s, ONE, TWO);   EQ(flags_of(&s), 1);   /* less: CF */
    EQ(s.of | s.sf | s.af, 0);
    sse_f64_ucomi(&s, TWO, ONE);   EQ(flags_of(&s), 0);   /* greater */
    sse_f64_ucomi(&s, PZERO, NZERO); EQ(flags_of(&s), 4); /* equal: ZF */
    sse_f64_ucomi(&s, QNAN1, ONE); EQ(flags_of(&s), 7);   /* unordered: ZF PF CF */
    EQ(sse_f64_cmp(ONE, ONE, 0), ~0ull);
    EQ(sse_f64_cmp(QNAN1, QNAN1, 0), 0);
    EQ(sse_f64_cmp(QNAN1, ONE, 3), ~0ull);
    EQ(sse_f64_cmp(QNAN1, ONE, 4), ~0ull);                /* NEQ is true when unordered */
    EQ(sse_f64_cmp(ONE, TWO, 1), ~0ull);
    EQ(sse_f64_cmp(TWO, TWO, 2), ~0ull);
    EQ(sse_f64_cmp(TWO, ONE, 6), ~0ull);                  /* NLE */
    EQ(sse_f64_cmp(QNAN1, ONE, 7), 0);
}

static void test_conversions(void) {
    /* CVTTSD2SI: truncation, and integer indefinite for NaN / out of range.
     * On ARM64 a plain C cast would saturate instead - these lines guard that. */
    EQ(sse_cvttsd2si(0xC00C000000000000ull, 64), (uint64_t)-3);          /* -3.5 -> -3 */
    EQ(sse_cvttsd2si(0x43E0000000000000ull, 64), I64_INDEFINITE);        /* 2^63 */
    EQ(sse_cvttsd2si(0x43DFFFFFFFFFFFFFull, 64), 0x7FFFFFFFFFFFFC00ull);  /* largest double < 2^63 */
    EQ(sse_cvttsd2si(0xC3E0000000000000ull, 64), 0x8000000000000000ull);  /* -2^63 is representable */
    EQ(sse_cvttsd2si(0xC3E0000000000001ull, 64), I64_INDEFINITE);
    EQ(sse_cvttsd2si(PINF, 64), I64_INDEFINITE);
    EQ(sse_cvttsd2si(QNAN1, 64), I64_INDEFINITE);
    EQ(sse_cvttsd2si(0x41DFFFFFFFC00000ull, 32), 0x7FFFFFFFu);           /* 2^31 - 1 */
    EQ(sse_cvttsd2si(0x41E0000000000000ull, 32), I32_INDEFINITE);        /* 2^31 */
    EQ(sse_cvttsd2si(0xC1E00000001FFFFFull, 32), 0x80000000u);           /* -2^31 - 0.99... */
    EQ(sse_cvttsd2si(0xC1E0000000200000ull, 32), I32_INDEFINITE);        /* -2^31 - 1 */
    EQ(sse_cvttsd2si(NINF, 32), I32_INDEFINITE);
    /* CVTSI2SD */
    EQ(sse_cvtsi2sd(0x7FFFFFFFFFFFFFFFull, 64), 0x43E0000000000000ull);  /* rounds up to 2^63 */
    EQ(sse_cvtsi2sd(9007199254740993ull, 64), 0x4340000000000000ull);    /* 2^53+1 -> 2^53 (ties-to-even) */
    EQ(sse_cvtsi2sd(0xFFFFFFFFull, 32), MONE);                           /* 32-bit -1 */
    EQ(sse_cvtsi2sd(0x123456789ull, 32), 0x41C1A2B3C4800000ull);         /* only the low 32 bits: 0x23456789 */
    /* CVTSD2SS / CVTSS2SD */
    EQ(sse_cvtsd2ss(0x3FB999999999999Aull), 0x3DCCCCCDu);                /* 0.1 */
    EQ(sse_cvtsd2ss(0x47EFFFFFF0000000ull), 0x7F800000u);                /* rounds past FLT_MAX -> inf */
    EQ(sse_cvtsd2ss(DMIN), 0);                                           /* underflow to +0 */
    EQ(sse_cvtsd2ss(0x7FF0000000000001ull), 0x7FC00000u);                /* SNaN, low payload dropped */
    EQ(sse_cvtsd2ss(0xFFF8000020000000ull), 0xFFC00001u);                /* payload bit 29 -> bit 0 */
    EQ(sse_cvtss2sd(0xBDCCCCCDu), 0xBFB99999A0000000ull);
    EQ(sse_cvtss2sd(0x7F800001u), 0x7FF8000020000000ull);                /* SNaN quieted, payload << 29 */
    EQ(sse_cvtss2sd(0x00000001u), 0x36A0000000000000ull);                /* float denormal is exact */
}

static uint8_t buf[64];
static guest_mem m;
static void misaligned(void) {
    x86_state s; memset(&s, 0, sizeof s); s.mem = &m;
    uint64_t lo, hi;
    sse_ld128(&s, 0x9008, 1, &lo, &hi);
}

int main(void) {
    test_nan_rules();
    test_ieee_cases();
    test_min_max();
    test_compare();
    test_conversions();
    memset(&m, 0, sizeof m);
    guest_map(&m, 0x9000, sizeof buf, buf, GUEST_PERM_R | GUEST_PERM_W, "buf");
    for (int i = 0; i < 16; i++) buf[0x10 + i] = (uint8_t)i;
    { x86_state s; memset(&s, 0, sizeof s); s.mem = &m; uint64_t lo, hi;
      sse_ld128(&s, 0x9010, 1, &lo, &hi); EQ(lo, 0x0706050403020100ull); EQ(hi, 0x0f0e0d0c0b0a0908ull); }
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) { int dn = open("/dev/null", O_WRONLY); dup2(dn, 2); misaligned(); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    EQ(WIFEXITED(st) ? WEXITSTATUS(st) : 255, 0x05);
    printf("checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
