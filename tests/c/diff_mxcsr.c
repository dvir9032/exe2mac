/* Differential test: runtime/softfloat.h vs. the real SSE unit under all 16
 * MXCSR settings (RC x FTZ x DAZ, all exceptions masked). Compares result
 * bits and the six sticky exception flags. TEST-ONLY ORACLE (x86-64 hosts). */
#if !defined(__x86_64__)
#include <stdio.h>
int main(void) { puts("SKIP: not an x86-64 host"); return 77; }
#else
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "runtime/x86_simd.h"

static uint64_t rng = 0x1234abcd9876ef01ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static long cases, failures;
static uint32_t cfg;                 /* MXCSR used for the hardware operation */
static uint32_t mx_after;

static void report(const char *op, uint64_t a, uint64_t b, uint64_t hr, uint64_t mr, unsigned hf, unsigned mf) {
    if (failures++ < 40)
        fprintf(stderr, "MISMATCH %-12s mxcsr=%04x a=%016" PRIx64 " b=%016" PRIx64 " hw=%016" PRIx64 "/%02x model=%016" PRIx64 "/%02x\n",
                op, cfg, a, b, hr, hf, mr, mf);
}
#define CHECK(op, a, b, hr, mr, mf) do { cases++; unsigned hf_ = mx_after & 0x3f; \
    if ((uint64_t)(hr) != (uint64_t)(mr) || hf_ != (mf)) report(op, a, b, hr, mr, hf_, mf); } while (0)

#define HW2(INSN, a, b, r) __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; " INSN " %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %4" \
                                            : "=r"(r) : "r"(a), "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory")
#define HW2S(INSN, a, b, r) __asm__ volatile("ldmxcsr %3; movd %k1, %%xmm0; movd %k2, %%xmm1; " INSN " %%xmm1, %%xmm0; movd %%xmm0, %k0; stmxcsr %4" \
                                             : "=r"(r) : "r"(a), "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory")

static uint64_t gen64(void) {
    uint64_t r = rnd(), sign = r & 0x8000000000000000ull, frac = rnd() & 0x000FFFFFFFFFFFFFull;
    unsigned e;
    switch ((r >> 1) & 7) {
    case 0: return rnd();
    case 1: e = (unsigned)((r >> 8) % 60); break;                       /* subnormal / tiny normal */
    case 2: e = 2047 - 1 - (unsigned)((r >> 8) % 60); break;            /* huge */
    case 3: e = 1023 - 30 + (unsigned)((r >> 8) % 60); break;           /* around 1 */
    case 4: {                                                            /* specials */
        static const uint64_t sp[] = { 0, 0x7FF0000000000000ull, 0x7FF8000000000000ull, 0x7FF4000000000001ull,
                                       0x0010000000000000ull, 0x000FFFFFFFFFFFFFull, 1, 0x7FEFFFFFFFFFFFFFull,
                                       0x3FF0000000000000ull, 0x0008000000000000ull };
        return sign | sp[(r >> 8) % (sizeof sp / sizeof sp[0])];
    }
    case 5: frac &= ~0xFFFFFFull; e = (unsigned)((r >> 8) % 2046) + 1; break;   /* short significand (exact ops) */
    default: e = (unsigned)((r >> 8) % 2048); if (e == 2047) e = 2046; break;
    }
    return sign | ((uint64_t)e << 52) | frac;
}
/* pairs whose product / quotient lands near the subnormal or overflow boundary */
static void gen_pair(uint64_t *a, uint64_t *b) {
    *a = gen64(); *b = gen64();
    uint64_t r = rnd();
    if ((r & 7) == 1) {
        /* min-normal x (1 - tiny): results just below 2^-1022 that may round up
         * to it - exactly where tininess before/after rounding differ */
        *a = (r & 0x8000000000000000ull) | 0x0010000000000000ull | ((r >> 8) & 0x3);
        *b = 0x3FEFFFFFFFFFFFFFull - ((r >> 12) & 0xF);
        if ((r >> 20) & 1) { uint64_t t = *a; *a = *b; *b = t; }
        return;
    }
    if ((r & 3) == 0) {
        int target = (r >> 4) & 1 ? (-1022 + (int)((r >> 8) % 120) - 60) : (1024 + (int)((r >> 8) % 8) - 4);
        int ea = (int)((r >> 20) % 1000) - 500;
        int eb = (r >> 2) & 1 ? target - ea : ea - target;          /* for mul : for div */
        if (ea + 1023 > 0 && ea + 1023 < 2047) *a = (*a & 0x800FFFFFFFFFFFFFull) | ((uint64_t)(ea + 1023) << 52);
        if (eb + 1023 > 0 && eb + 1023 < 2047) *b = (*b & 0x800FFFFFFFFFFFFFull) | ((uint64_t)(eb + 1023) << 52);
    }
}
static uint32_t gen32(void) {
    uint64_t r = rnd();
    uint32_t sign = (uint32_t)r & 0x80000000u, frac = (uint32_t)(rnd() & 0x7FFFFF);
    unsigned e;
    switch ((r >> 1) & 7) {
    case 0: return (uint32_t)rnd();
    case 1: e = (unsigned)((r >> 8) % 30); break;
    case 2: e = 254 - (unsigned)((r >> 8) % 30); break;
    case 3: { static const uint32_t sp[] = { 0, 0x7F800000u, 0x7FC00000u, 0x7FA00001u, 0x00800000u, 0x007FFFFFu, 1, 0x7F7FFFFFu };
              return sign | sp[(r >> 8) % 8]; }
    default: e = (unsigned)((r >> 8) % 255); break;
    }
    return sign | (e << 23) | frac;
}

static void check_cfg(void) {
    sf_env env = sf_env_of(cfg);
    for (int k = 0; k < 40000; k++) {
        uint64_t a, b, r, m;
        unsigned fl;
        gen_pair(&a, &b);
#define OP64(NAME, INSN, EXPR) HW2(INSN, a, b, r); fl = 0; m = EXPR; CHECK(NAME, a, b, r, m, fl);
        OP64("addsd", "addsd", sf_add(&SF_F64, &env, a, b, 0, &fl))
        OP64("subsd", "subsd", sf_add(&SF_F64, &env, a, b, 1, &fl))
        OP64("mulsd", "mulsd", sf_mul(&SF_F64, &env, a, b, &fl))
        OP64("divsd", "divsd", sf_div(&SF_F64, &env, a, b, &fl))
        HW2("sqrtsd", a, b, r); fl = 0; m = sf_sqrt(&SF_F64, &env, b, &fl); CHECK("sqrtsd", b, 0, r, m, fl);
        /* conversions */
        uint32_t r32;
        __asm__ volatile("ldmxcsr %2; movq %1, %%xmm1; cvtsd2ss %%xmm1, %%xmm0; movd %%xmm0, %0; stmxcsr %3"
                         : "=r"(r32) : "r"(a), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory");
        fl = 0; m = sf_f64_to_f32(&env, a, &fl); CHECK("cvtsd2ss", a, 0, r32, m, fl);
        uint64_t i64; uint32_t i32;
        __asm__ volatile("ldmxcsr %2; movq %1, %%xmm0; cvttsd2si %%xmm0, %0; stmxcsr %3"
                         : "=r"(i64) : "r"(a), "m"(cfg), "m"(mx_after) : "xmm0", "memory");
        fl = 0; m = sf_to_int(&SF_F64, &env, a, 64, 1, &fl); CHECK("cvttsd2si64", a, 0, i64, m, fl);
        __asm__ volatile("ldmxcsr %2; movq %1, %%xmm0; cvtsd2si %%xmm0, %0; stmxcsr %3"
                         : "=r"(i64) : "r"(a), "m"(cfg), "m"(mx_after) : "xmm0", "memory");
        fl = 0; m = sf_to_int(&SF_F64, &env, a, 64, 0, &fl); CHECK("cvtsd2si64", a, 0, i64, m, fl);
        __asm__ volatile("ldmxcsr %2; movq %1, %%xmm0; cvtsd2si %%xmm0, %k0; stmxcsr %3"
                         : "=r"(i32) : "r"(a), "m"(cfg), "m"(mx_after) : "xmm0", "memory");
        fl = 0; m = sf_to_int(&SF_F64, &env, a, 32, 0, &fl); CHECK("cvtsd2si32", a, 0, i32, m, fl);
        __asm__ volatile("ldmxcsr %2; cvtsi2sdq %1, %%xmm0; movq %%xmm0, %0; stmxcsr %3"
                         : "=r"(r) : "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "memory");
        fl = 0; m = sf_from_int(&SF_F64, &env, (int64_t)b, &fl); CHECK("cvtsi2sd64", b, 0, r, m, fl);
        __asm__ volatile("ldmxcsr %2; cvtsi2ssq %1, %%xmm0; movd %%xmm0, %k0; stmxcsr %3"
                         : "=r"(r32) : "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "memory");
        fl = 0; m = sf_from_int(&SF_F32, &env, (int64_t)b, &fl); CHECK("cvtsi2ss64", b, 0, r32, m, fl);
        /* binary32 */
        uint32_t x = gen32(), y = gen32();
        if ((k & 7) == 3) { x = (uint32_t)(rnd() & 0x80000000u) | 0x00800000u | (uint32_t)(rnd() & 3); y = 0x3F7FFFFFu - (uint32_t)(rnd() & 0xF); }
#define OP32(NAME, INSN, EXPR) HW2S(INSN, x, y, r32); fl = 0; m = EXPR; CHECK(NAME, x, y, r32, m, fl);
        OP32("addss", "addss", sf_add(&SF_F32, &env, x, y, 0, &fl))
        OP32("subss", "subss", sf_add(&SF_F32, &env, x, y, 1, &fl))
        OP32("mulss", "mulss", sf_mul(&SF_F32, &env, x, y, &fl))
        OP32("divss", "divss", sf_div(&SF_F32, &env, x, y, &fl))
        HW2S("sqrtss", x, y, r32); fl = 0; m = sf_sqrt(&SF_F32, &env, y, &fl); CHECK("sqrtss", y, 0, r32, m, fl);
        /* compare-type instructions through the x86_sse.h wrappers */
        {
            x86_state st; memset(&st, 0, sizeof st);
#define WRAP(NAME, INSN, CALL) HW2(INSN, a, b, r); st.mxcsr = cfg; m = CALL; CHECK(NAME, a, b, r, m, st.mxcsr & 0x3f);
            WRAP("maxsd", "maxsd", sse_f64_max(&st, a, b))
            WRAP("minsd", "minsd", sse_f64_min(&st, a, b))
#define CMPP(P) WRAP("cmpsd" #P, "cmpsd $" #P ",", sse_f64_cmp(&st, a, b, P))
            CMPP(0) CMPP(1) CMPP(2) CMPP(3) CMPP(4) CMPP(5) CMPP(6) CMPP(7)
            uint64_t ef;
            __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; ucomisd %%xmm1, %%xmm0; pushfq; popq %0; stmxcsr %4"
                             : "=r"(ef) : "r"(a), "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "cc", "memory");
            st.mxcsr = cfg; sse_f64_ucomi(&st, a, b);
            m = (uint64_t)st.cf | ((uint64_t)st.pf << 2) | ((uint64_t)st.af << 4) | ((uint64_t)st.zf << 6) | ((uint64_t)st.sf << 7) | ((uint64_t)st.of << 11);
            CHECK("ucomisd", a, b, ef & 0x8d5, m, st.mxcsr & 0x3f);
            __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; comisd %%xmm1, %%xmm0; pushfq; popq %0; stmxcsr %4"
                             : "=r"(ef) : "r"(a), "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "cc", "memory");
            st.mxcsr = cfg; sse_f64_comi(&st, a, b);
            m = (uint64_t)st.cf | ((uint64_t)st.pf << 2) | ((uint64_t)st.af << 4) | ((uint64_t)st.zf << 6) | ((uint64_t)st.sf << 7) | ((uint64_t)st.of << 11);
            CHECK("comisd", a, b, ef & 0x8d5, m, st.mxcsr & 0x3f);
            /* packed: flags of both lanes accumulate */
            v128 va = { a, b }, vb = { b, gen64() }, vr;
            __asm__ volatile("ldmxcsr %3; movdqu %1, %%xmm0; movdqu %2, %%xmm1; mulpd %%xmm1, %%xmm0; movdqu %%xmm0, %0; stmxcsr %4"
                             : "=m"(vr) : "m"(va), "m"(vb), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory");
            st.mxcsr = cfg; v128 mv = v_fp64(&st, va, vb, SSE_MUL);
            CHECK("mulpd.lo", a, b, vr.lo, mv.lo, st.mxcsr & 0x3f);
            CHECK("mulpd.hi", b, vb.hi, vr.hi, mv.hi, st.mxcsr & 0x3f);
        }
        __asm__ volatile("ldmxcsr %2; movd %k1, %%xmm1; cvtss2sd %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %3"
                         : "=r"(r) : "r"(x), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory");
        fl = 0; m = sf_f32_to_f64(&env, x, &fl); CHECK("cvtss2sd", x, 0, r, m, fl);
    }
}

int main(void) {
    uint32_t saved;
    __asm__ volatile("stmxcsr %0" : "=m"(saved));
    for (unsigned rc = 0; rc < 4; rc++)
        for (unsigned ftz = 0; ftz < 2; ftz++)
            for (unsigned daz = 0; daz < 2; daz++) {
                cfg = 0x1F80u | (rc << 13) | (ftz << 15) | (daz << 6);
                check_cfg();
            }
    __asm__ volatile("ldmxcsr %0" : : "m"(saved));
    printf("mxcsr differential cases=%ld failures=%ld\n", cases, failures);
    return failures ? 1 : 0;
}
#endif
