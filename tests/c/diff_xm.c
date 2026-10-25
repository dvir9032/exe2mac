/* Differential test: unmasked SSE floating-point exceptions (#XM).
 * Runs each operation on the real SSE unit with random MXCSR settings where
 * one or more exceptions are unmasked, catches SIGFPE and reads the MXCSR the
 * kernel saved at the fault. The model (runtime/x86_sse.h wrappers) must:
 *   - fault exactly when the hardware faults,
 *   - leave exactly the hardware's six flag bits in MXCSR at the fault,
 *   - pick the NTSTATUS of the highest-priority unmasked flag the hardware set,
 *   - and otherwise produce the same result bits and flags.
 * TEST-ONLY ORACLE (x86-64 Linux hosts). */
#if !defined(__x86_64__) || !defined(__linux__)
#include <stdio.h>
int main(void) { puts("SKIP: needs an x86-64 Linux host"); return 77; }
#else
#define _GNU_SOURCE
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>

/* the model's #XM lands here instead of ending the process */
#define exe2mac_raise diff_xm_raise
#include "runtime/x86_simd.h"

static jmp_buf model_jb;
static uint32_t model_status;
_Noreturn void exe2mac_raise(const x86_state *s, uint32_t ntstatus, const char *what) {
    (void)s; (void)what; model_status = ntstatus; longjmp(model_jb, 1);
}

static sigjmp_buf hw_jb;
static volatile uint32_t hw_fault_mxcsr;
static void on_fpe(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)si;
    ucontext_t *uc = ctx;
    hw_fault_mxcsr = uc->uc_mcontext.fpregs->mxcsr;
    siglongjmp(hw_jb, 1);
}

static uint64_t rng = 0x5eed0f00dcafe123ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static long cases, faults, failures;
static uint32_t cfg, mx_after;
static const uint32_t DEF = 0x1F80u;

static uint32_t status_of(unsigned flags) {
    static const uint32_t st[6] = { 0xC0000090u, 0xC000008Du, 0xC000008Eu, 0xC0000091u, 0xC0000093u, 0xC000008Fu };
    unsigned u = flags & ~(cfg >> 7) & 0x3f;
    for (unsigned i = 0; i < 6; i++) if (u & (1u << i)) return st[i];
    return 0;
}

static void compare(const char *op, uint64_t a, uint64_t b, int hw_trap, uint64_t hr, unsigned hf,
                    int m_trap, uint64_t mr, unsigned mf) {
    cases++;
    if (hw_trap) faults++;
    int bad = hw_trap != m_trap || hf != mf || (!hw_trap && hr != mr) ||
              (hw_trap && model_status != status_of(hf));
    if (bad && failures++ < 40)
        fprintf(stderr, "MISMATCH %-10s mxcsr=%04x a=%016" PRIx64 " b=%016" PRIx64
                " hw=%s %016" PRIx64 "/%02x model=%s %016" PRIx64 "/%02x status=%08x\n",
                op, cfg, a, b, hw_trap ? "TRAP" : "ok", hr, hf, m_trap ? "TRAP" : "ok", mr, mf, model_status);
}

/* HW(asm): run one instruction sequence; afterwards hw_trap/hw_flags are set */
#define HW(...) do {                                                              \
        if (!sigsetjmp(hw_jb, 1)) { __VA_ARGS__; hw_trap = 0; hw_flags = mx_after & 0x3f; } \
        else { hw_trap = 1; hw_flags = hw_fault_mxcsr & 0x3f; hr = 0;              \
               __asm__ volatile("ldmxcsr %0" : : "m"(DEF)); }                     \
    } while (0)
/* MODEL(expr): evaluate with the x86_state wrappers; st.mxcsr starts at cfg */
#define MODEL(EXPR) do {                                                          \
        memset(&st, 0, sizeof st); st.mxcsr = cfg; model_status = 0;              \
        if (!setjmp(model_jb)) { mr = (EXPR); m_trap = 0; } else { m_trap = 1; mr = 0; } \
    } while (0)
#define CHECK(NAME, A, B) compare(NAME, A, B, hw_trap, hr, hw_flags, m_trap, mr, st.mxcsr & 0x3f)

#define BIN64(INSN) HW(__asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; " INSN " %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %4" \
                     : "=r"(hr) : "r"(a), "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory"))
#define BIN32(INSN) HW(__asm__ volatile("ldmxcsr %3; movd %k1, %%xmm0; movd %k2, %%xmm1; " INSN " %%xmm1, %%xmm0; movd %%xmm0, %k0; stmxcsr %4" \
                     : "=r"(hr) : "r"(x), "r"(y), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory"))

static uint64_t gen64(void) {
    uint64_t r = rnd(), sign = r & 0x8000000000000000ull, frac = rnd() & 0x000FFFFFFFFFFFFFull;
    unsigned e;
    switch ((r >> 1) & 7) {
    case 0: return rnd();
    case 1: e = (unsigned)((r >> 8) % 60); break;
    case 2: e = 2046 - (unsigned)((r >> 8) % 60); break;
    case 3: e = 1023 - 30 + (unsigned)((r >> 8) % 60); break;
    case 4: {
        static const uint64_t sp[] = { 0, 0x7FF0000000000000ull, 0x7FF8000000000000ull, 0x7FF4000000000001ull,
                                       0x0010000000000000ull, 0x000FFFFFFFFFFFFFull, 1, 0x7FEFFFFFFFFFFFFFull,
                                       0x3FF0000000000000ull, 0x0008000000000000ull, 0x4008000000000000ull };
        return sign | sp[(r >> 8) % (sizeof sp / sizeof sp[0])];
    }
    case 5: frac &= ~0xFFFFFFull; e = (unsigned)((r >> 8) % 2046) + 1; break;   /* exact-ish */
    default: e = (unsigned)((r >> 8) % 2047); break;
    }
    return sign | ((uint64_t)e << 52) | frac;
}
static void gen_pair(uint64_t *a, uint64_t *b) {
    *a = gen64(); *b = gen64();
    uint64_t r = rnd();
    if ((r & 3) == 0) {            /* steer products / quotients to the underflow or overflow edge */
        int target = (r >> 4) & 1 ? (-1022 + (int)((r >> 8) % 120) - 60) : (1024 + (int)((r >> 8) % 8) - 4);
        int ea = (int)((r >> 20) % 1000) - 500;
        int eb = (r >> 2) & 1 ? target - ea : ea - target;
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

/* file-scope so setjmp/longjmp cannot clobber them */
static x86_state st;
static uint64_t a, b, hr, mr;
static uint32_t x, y;
static int hw_trap, m_trap;
static unsigned hw_flags;

static void one_round(void) {
    gen_pair(&a, &b);
    BIN64("addsd"); MODEL(sse_f64_arith(&st, a, b, SSE_ADD)); CHECK("addsd", a, b);
    BIN64("subsd"); MODEL(sse_f64_arith(&st, a, b, SSE_SUB)); CHECK("subsd", a, b);
    BIN64("mulsd"); MODEL(sse_f64_arith(&st, a, b, SSE_MUL)); CHECK("mulsd", a, b);
    BIN64("divsd"); MODEL(sse_f64_arith(&st, a, b, SSE_DIV)); CHECK("divsd", a, b);
    BIN64("sqrtsd"); MODEL(sse_f64_sqrt(&st, b)); CHECK("sqrtsd", b, 0);
    BIN64("maxsd"); MODEL(sse_f64_max(&st, a, b)); CHECK("maxsd", a, b);
    BIN64("minsd"); MODEL(sse_f64_min(&st, a, b)); CHECK("minsd", a, b);
    BIN64("cmpsd $1,"); MODEL(sse_f64_cmp(&st, a, b, 1)); CHECK("cmpltsd", a, b);
    BIN64("cmpsd $0,"); MODEL(sse_f64_cmp(&st, a, b, 0)); CHECK("cmpeqsd", a, b);
    HW(__asm__ volatile("ldmxcsr %2; movq %1, %%xmm1; cvtsd2ss %%xmm1, %%xmm0; movd %%xmm0, %k0; stmxcsr %3"
                        : "=r"(hr) : "r"(a), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory"));
    MODEL(sse_cvtsd2ss(&st, a)); CHECK("cvtsd2ss", a, 0);
    HW(__asm__ volatile("ldmxcsr %2; movq %1, %%xmm0; cvtsd2si %%xmm0, %0; stmxcsr %3"
                        : "=r"(hr) : "r"(a), "m"(cfg), "m"(mx_after) : "xmm0", "memory"));
    MODEL(sse_cvtsd2si(&st, a, 64)); CHECK("cvtsd2si", a, 0);
    HW(__asm__ volatile("ldmxcsr %2; movq %1, %%xmm0; cvttsd2si %%xmm0, %k0; stmxcsr %3"
                        : "=r"(hr) : "r"(a), "m"(cfg), "m"(mx_after) : "xmm0", "memory"));
    hr &= 0xffffffffu;
    MODEL(sse_cvttsd2si(&st, a, 32)); CHECK("cvttsd2si32", a, 0);
    HW(__asm__ volatile("ldmxcsr %2; cvtsi2sdq %1, %%xmm0; movq %%xmm0, %0; stmxcsr %3"
                        : "=r"(hr) : "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "memory"));
    MODEL(sse_cvtsi2sd(&st, b, 64)); CHECK("cvtsi2sd", b, 0);
    {   /* comisd / ucomisd: compare EFLAGS-derived bits */
        uint64_t ef;
        HW(__asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; comisd %%xmm1, %%xmm0; pushfq; popq %0; stmxcsr %4"
                            : "=r"(ef) : "r"(a), "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "cc", "memory"); hr = ef & 0x45);
        MODEL((sse_f64_comi(&st, a, b), (uint64_t)st.cf | ((uint64_t)st.pf << 2) | ((uint64_t)st.zf << 6)));
        CHECK("comisd", a, b);
        HW(__asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; ucomisd %%xmm1, %%xmm0; pushfq; popq %0; stmxcsr %4"
                            : "=r"(ef) : "r"(a), "r"(b), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "cc", "memory"); hr = ef & 0x45);
        MODEL((sse_f64_ucomi(&st, a, b), (uint64_t)st.cf | ((uint64_t)st.pf << 2) | ((uint64_t)st.zf << 6)));
        CHECK("ucomisd", a, b);
    }
    {   /* packed: an unmasked exception in either lane faults, flags of both lanes count */
        v128 va = { a, gen64() }, vb = { b, gen64() }, vr;
        HW(__asm__ volatile("ldmxcsr %3; movdqu %1, %%xmm0; movdqu %2, %%xmm1; mulpd %%xmm1, %%xmm0; movdqu %%xmm0, %0; stmxcsr %4"
                            : "=m"(vr) : "m"(va), "m"(vb), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory"); hr = vr.lo ^ (vr.hi * 3));
        MODEL(({ v128 mv = v_fp64(&st, va, vb, SSE_MUL); mv.lo ^ (mv.hi * 3); }));
        CHECK("mulpd", a, b);
        HW(__asm__ volatile("ldmxcsr %3; movdqu %1, %%xmm0; movdqu %2, %%xmm1; addpd %%xmm1, %%xmm0; movdqu %%xmm0, %0; stmxcsr %4"
                            : "=m"(vr) : "m"(va), "m"(vb), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory"); hr = vr.lo ^ (vr.hi * 3));
        MODEL(({ v128 mv = v_fp64(&st, va, vb, SSE_ADD); mv.lo ^ (mv.hi * 3); }));
        CHECK("addpd", a, b);
    }
    x = gen32(); y = gen32();
    BIN32("addss"); MODEL(sse_f32_arith(&st, x, y, SSE_ADD)); CHECK("addss", x, y);
    BIN32("mulss"); MODEL(sse_f32_arith(&st, x, y, SSE_MUL)); CHECK("mulss", x, y);
    BIN32("divss"); MODEL(sse_f32_arith(&st, x, y, SSE_DIV)); CHECK("divss", x, y);
    HW(__asm__ volatile("ldmxcsr %2; movd %k1, %%xmm1; cvtss2sd %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %3"
                        : "=r"(hr) : "r"(x), "m"(cfg), "m"(mx_after) : "xmm0", "xmm1", "memory"));
    MODEL(sse_cvtss2sd(&st, x)); CHECK("cvtss2sd", x, 0);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fpe;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGFPE, &sa, 0);
    for (int k = 0; k < 400000; k++) {
        uint64_t r = rnd();
        unsigned masks = (unsigned)(r & 0x3f);
        if (masks == 0x3f) masks &= ~(1u << ((r >> 6) % 6));          /* at least one unmasked */
        cfg = (masks << 7) | ((unsigned)((r >> 9) & 3) << 13) | ((unsigned)((r >> 11) & 1) << 15) |
              ((unsigned)((r >> 12) & 1) << 6);
        one_round();
    }
    __asm__ volatile("ldmxcsr %0" : : "m"(DEF));
    printf("xm differential cases=%ld faults=%ld failures=%ld\n", cases, faults, failures);
    return failures ? 1 : 0;
}
#endif
