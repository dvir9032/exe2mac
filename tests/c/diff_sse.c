/* Differential test: runtime/x86_sse.h vs. the real x86-64 SSE unit.
 * TEST-ONLY ORACLE (x86-64 hosts only); never part of a translated program.
 * Compares exact result bits, including NaN payloads and signs. */
#if !defined(__x86_64__)
#include <stdio.h>
int main(void) { puts("SKIP: not an x86-64 host"); return 77; }
#else
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "runtime/x86_sse.h"

/* guest state with the Windows default MXCSR (0x1F80: all exceptions masked) */
static x86_state G = { .mxcsr = 0x1F80u };

static uint64_t rng = 0x243f6a8885a308d3ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static long cases, failures;
static void report(const char *op, uint64_t a, uint64_t b, uint64_t hw, uint64_t model) {
    if (failures++ < 25)
        fprintf(stderr, "MISMATCH %s a=%016" PRIx64 " b=%016" PRIx64 " hw=%016" PRIx64 " model=%016" PRIx64 "\n",
                op, a, b, hw, model);
}
#define CMP(op, a, b, hw, model) do { cases++; if ((uint64_t)(hw) != (uint64_t)(model)) report(op, a, b, hw, model); } while (0)

static const uint64_t special64[] = {
    0x0000000000000000ull, 0x8000000000000000ull, 0x7FF0000000000000ull, 0xFFF0000000000000ull,
    0x7FF8000000000000ull, 0xFFF8000000000000ull, 0x7FF8000000000123ull, 0xFFFC00000000ABCDull,
    0x7FF0000000000001ull, 0xFFF4000000000077ull,                         /* SNaNs */
    0x0000000000000001ull, 0x000FFFFFFFFFFFFFull, 0x0010000000000000ull, 0x7FEFFFFFFFFFFFFFull,
    0x3FF0000000000000ull, 0xBFF0000000000000ull, 0x3FB999999999999Aull, 0x4000000000000000ull,
    0x43E0000000000000ull, 0xC3E0000000000000ull, 0x43DFFFFFFFFFFFFFull, 0xC3E0000000000001ull, /* +-2^63 edges */
    0x41E0000000000000ull, 0xC1E0000000000000ull, 0x41DFFFFFFFC00000ull, 0xC1E0000000200000ull, /* +-2^31 edges */
    0xC1E00000001FFFFFull, 0x3FE0000000000000ull, 0xBFE0000000000000ull, 0x3FF8000000000000ull,
};
#define NS (sizeof special64 / sizeof special64[0])

static uint64_t pick64(void) {
    uint64_t r = rnd();
    switch (r & 7) {
    case 0: case 1: return special64[(r >> 8) % NS];
    case 2: return (r & 0x800FFFFFFFFFFFFFull) | ((0x3F0ull + ((r >> 20) & 0x1F)) << 52);  /* near 1 */
    case 3: return r & 0x800FFFFFFFFFFFFFull;                                            /* denormal */
    default: return rnd();
    }
}
static uint32_t pick32(void) {
    static const uint32_t sp[] = { 0, 0x80000000u, 0x7F800000u, 0xFF800000u, 0x7FC00000u, 0xFFC00000u,
                                   0x7FC01234u, 0x7F800001u, 0xFFA00005u, 1, 0x007FFFFFu, 0x00800000u,
                                   0x7F7FFFFFu, 0x3F800000u, 0xBDCCCCCDu, 0x3FC00000u };
    uint64_t r = rnd();
    switch (r & 3) {
    case 0: return sp[(r >> 8) % (sizeof sp / sizeof sp[0])];
    case 1: return (uint32_t)((r >> 16) & 0x807FFFFFu) | (uint32_t)((0x78u + ((r >> 40) & 0xF)) << 23);
    default: return (uint32_t)rnd();
    }
}

#define HW2(INSN, a, b, r) __asm__ volatile("movq %1, %%xmm0; movq %2, %%xmm1; " INSN " %%xmm1, %%xmm0; movq %%xmm0, %0" \
                                            : "=r"(r) : "r"(a), "r"(b) : "xmm0", "xmm1")
#define HW2S(INSN, a, b, r) __asm__ volatile("movd %k1, %%xmm0; movd %k2, %%xmm1; " INSN " %%xmm1, %%xmm0; movd %%xmm0, %k0" \
                                             : "=r"(r) : "r"(a), "r"(b) : "xmm0", "xmm1")

static void check_f64(uint64_t a, uint64_t b) {
    uint64_t r;
    HW2("addsd", a, b, r); CMP("addsd", a, b, r, sse_f64_arith(&G, a, b, SSE_ADD));
    HW2("subsd", a, b, r); CMP("subsd", a, b, r, sse_f64_arith(&G, a, b, SSE_SUB));
    HW2("mulsd", a, b, r); CMP("mulsd", a, b, r, sse_f64_arith(&G, a, b, SSE_MUL));
    HW2("divsd", a, b, r); CMP("divsd", a, b, r, sse_f64_arith(&G, a, b, SSE_DIV));
    HW2("maxsd", a, b, r); CMP("maxsd", a, b, r, sse_f64_max(&G, a, b));
    HW2("minsd", a, b, r); CMP("minsd", a, b, r, sse_f64_min(&G, a, b));
    HW2("sqrtsd", a, b, r);                     /* xmm0 = sqrt(xmm1) */
    CMP("sqrtsd", b, 0, r, sse_f64_sqrt(&G, b));
#define CMPSD(P) HW2("cmpsd $" #P ",", a, b, r); CMP("cmpsd" #P, a, b, r, sse_f64_cmp(&G, a, b, P));
    CMPSD(0) CMPSD(1) CMPSD(2) CMPSD(3) CMPSD(4) CMPSD(5) CMPSD(6) CMPSD(7)
    /* UCOMISD / COMISD flags */
    uint64_t f;
    __asm__ volatile("movq %1, %%xmm0; movq %2, %%xmm1; ucomisd %%xmm1, %%xmm0; pushfq; popq %0"
                     : "=r"(f) : "r"(a), "r"(b) : "xmm0", "xmm1", "cc");
    x86_state s; memset(&s, 0, sizeof s); s.mxcsr = 0x1F80u; s.af = s.sf = s.of = 1;
    sse_f64_ucomi(&s, a, b);
    uint64_t mf = (uint64_t)s.cf | ((uint64_t)s.pf << 2) | ((uint64_t)s.af << 4) | ((uint64_t)s.zf << 6) |
                  ((uint64_t)s.sf << 7) | ((uint64_t)s.of << 11);
    CMP("ucomisd", a, b, f & 0x8D5, mf);
    __asm__ volatile("movq %1, %%xmm0; movq %2, %%xmm1; comisd %%xmm1, %%xmm0; pushfq; popq %0"
                     : "=r"(f) : "r"(a), "r"(b) : "xmm0", "xmm1", "cc");
    CMP("comisd", a, b, f & 0x8D5, mf);
    /* conversions from double */
    uint64_t i64; uint32_t i32;
    __asm__ volatile("movq %1, %%xmm0; cvttsd2si %%xmm0, %0" : "=r"(i64) : "r"(a) : "xmm0");
    CMP("cvttsd2si64", a, 0, i64, sse_cvttsd2si(&G, a, 64));
    __asm__ volatile("movq %1, %%xmm0; cvttsd2si %%xmm0, %k0" : "=r"(i32) : "r"(a) : "xmm0");
    CMP("cvttsd2si32", a, 0, i32, sse_cvttsd2si(&G, a, 32));
    __asm__ volatile("movq %1, %%xmm1; cvtsd2ss %%xmm1, %%xmm0; movd %%xmm0, %k0" : "=r"(i32) : "r"(a) : "xmm0", "xmm1");
    CMP("cvtsd2ss", a, 0, i32, sse_cvtsd2ss(&G, a));
    /* integer -> double (use the raw random bits as the integer) */
    __asm__ volatile("cvtsi2sdq %1, %%xmm0; movq %%xmm0, %0" : "=r"(r) : "r"(b) : "xmm0");
    CMP("cvtsi2sd64", b, 0, r, sse_cvtsi2sd(&G, b, 64));
    __asm__ volatile("cvtsi2sdl %k1, %%xmm0; movq %%xmm0, %0" : "=r"(r) : "r"(b) : "xmm0");
    CMP("cvtsi2sd32", b, 0, r, sse_cvtsi2sd(&G, b, 32));
}

static void check_f32(uint32_t a, uint32_t b) {
    uint32_t r; uint64_t d;
    HW2S("addss", a, b, r); CMP("addss", a, b, r, sse_f32_arith(&G, a, b, SSE_ADD));
    HW2S("subss", a, b, r); CMP("subss", a, b, r, sse_f32_arith(&G, a, b, SSE_SUB));
    HW2S("mulss", a, b, r); CMP("mulss", a, b, r, sse_f32_arith(&G, a, b, SSE_MUL));
    HW2S("divss", a, b, r); CMP("divss", a, b, r, sse_f32_arith(&G, a, b, SSE_DIV));
    __asm__ volatile("movd %k1, %%xmm1; cvtss2sd %%xmm1, %%xmm0; movq %%xmm0, %0" : "=r"(d) : "r"(a) : "xmm0", "xmm1");
    CMP("cvtss2sd", a, 0, d, sse_cvtss2sd(&G, a));
}

int main(void) {
    uint32_t mxcsr;
    __asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
    if ((mxcsr & 0xFFC0u) != 0x1F80u) { printf("unexpected MXCSR 0x%x\n", mxcsr); return 2; }
    for (unsigned i = 0; i < NS; i++)
        for (unsigned j = 0; j < NS; j++) check_f64(special64[i], special64[j]);
    for (int k = 0; k < 300000; k++) check_f64(pick64(), pick64());
    for (int k = 0; k < 300000; k++) check_f32(pick32(), pick32());
    printf("sse differential cases=%ld failures=%ld\n", cases, failures);
    return failures ? 1 : 0;
}
#endif
