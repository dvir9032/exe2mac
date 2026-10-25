/* Differential test: runtime/x86_simd.h vs. the real SSE2 unit.
 * TEST-ONLY ORACLE (x86-64 hosts only). Compares all 128 result bits. */
#if !defined(__x86_64__)
#include <stdio.h>
int main(void) { puts("SKIP: not an x86-64 host"); return 77; }
#else
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "runtime/x86_simd.h"

/* guest state with the Windows default MXCSR (0x1F80: all exceptions masked) */
static x86_state G = { .mxcsr = 0x1F80u };

static uint64_t rng = 0xb5ad4eceda1ce2a9ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static long cases, failures;

static uint64_t pick64(void) {
    static const uint8_t sp[] = { 0x00, 0x01, 0x7f, 0x80, 0xff, 0xfe, 0x40, 0x3f };
    uint64_t r = rnd();
    if ((r & 3) == 0) return rnd();
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)((r >> (8 + i)) & 1 ? sp[(rnd() >> 3) & 7] : (uint8_t)rnd()) << (8 * i);
    return v;
}
static v128 pickv(void) { v128 v = { pick64(), pick64() }; return v; }

static void report(const char *op, v128 a, v128 b, v128 hw, v128 m) {
    if (failures++ < 25)
        fprintf(stderr, "MISMATCH %s a=%016" PRIx64 "%016" PRIx64 " b=%016" PRIx64 "%016" PRIx64
                " hw=%016" PRIx64 "%016" PRIx64 " model=%016" PRIx64 "%016" PRIx64 "\n",
                op, a.hi, a.lo, b.hi, b.lo, hw.hi, hw.lo, m.hi, m.lo);
}
#define CHECKV(op, a, b, hw, m) do { v128 _h = (hw), _m = (m); cases++; \
    if (_h.lo != _m.lo || _h.hi != _m.hi) report(op, a, b, _h, _m); } while (0)

#define HW2(INSN) ({ v128 _r; __asm__ volatile("movdqu %1, %%xmm0; movdqu %2, %%xmm1; " INSN " %%xmm1, %%xmm0; movdqu %%xmm0, %0" \
                     : "=m"(_r) : "m"(a), "m"(b) : "xmm0", "xmm1"); _r; })
#define HWI(INSN) ({ v128 _r; __asm__ volatile("movdqu %1, %%xmm1; " INSN ", %%xmm1, %%xmm0; movdqu %%xmm0, %0" \
                     : "=m"(_r) : "m"(b) : "xmm0", "xmm1"); _r; })
#define HWS(INSN) ({ v128 _r; __asm__ volatile("movdqu %1, %%xmm0; " INSN ", %%xmm0; movdqu %%xmm0, %0" \
                     : "=m"(_r) : "m"(a) : "xmm0"); _r; })
#define HWSH(INSN) ({ v128 _r; __asm__ volatile("movdqu %1, %%xmm0; movdqu %2, %%xmm1; " INSN " %%xmm1, %%xmm0; movdqu %%xmm0, %0" \
                     : "=m"(_r) : "m"(a), "m"(cnt) : "xmm0", "xmm1"); _r; })

static void check(v128 a, v128 b) {
    CHECKV("paddb", a, b, HW2("paddb"), v_add(a, b, 8));
    CHECKV("paddw", a, b, HW2("paddw"), v_add(a, b, 16));
    CHECKV("paddd", a, b, HW2("paddd"), v_add(a, b, 32));
    CHECKV("paddq", a, b, HW2("paddq"), v_add(a, b, 64));
    CHECKV("psubb", a, b, HW2("psubb"), v_sub(a, b, 8));
    CHECKV("psubw", a, b, HW2("psubw"), v_sub(a, b, 16));
    CHECKV("psubd", a, b, HW2("psubd"), v_sub(a, b, 32));
    CHECKV("psubq", a, b, HW2("psubq"), v_sub(a, b, 64));
    CHECKV("pmullw", a, b, HW2("pmullw"), v_mullw(a, b));
    CHECKV("pmuludq", a, b, HW2("pmuludq"), v_muludq(a, b));
    CHECKV("pcmpeqb", a, b, HW2("pcmpeqb"), v_cmpeq(a, b, 8));
    CHECKV("pcmpeqw", a, b, HW2("pcmpeqw"), v_cmpeq(a, b, 16));
    CHECKV("pcmpeqd", a, b, HW2("pcmpeqd"), v_cmpeq(a, b, 32));
    CHECKV("pcmpgtb", a, b, HW2("pcmpgtb"), v_cmpgt(a, b, 8));
    CHECKV("pcmpgtw", a, b, HW2("pcmpgtw"), v_cmpgt(a, b, 16));
    CHECKV("pcmpgtd", a, b, HW2("pcmpgtd"), v_cmpgt(a, b, 32));
    CHECKV("pminub", a, b, HW2("pminub"), v_minmax(a, b, 8, 0, 0));
    CHECKV("pmaxub", a, b, HW2("pmaxub"), v_minmax(a, b, 8, 0, 1));
    CHECKV("pminsw", a, b, HW2("pminsw"), v_minmax(a, b, 16, 1, 0));
    CHECKV("pmaxsw", a, b, HW2("pmaxsw"), v_minmax(a, b, 16, 1, 1));
    CHECKV("packuswb", a, b, HW2("packuswb"), v_pack(a, b, 16, 1));
    CHECKV("packsswb", a, b, HW2("packsswb"), v_pack(a, b, 16, 0));
    CHECKV("packssdw", a, b, HW2("packssdw"), v_pack(a, b, 32, 0));
    CHECKV("punpcklbw", a, b, HW2("punpcklbw"), v_unpack(a, b, 8, 0));
    CHECKV("punpckhbw", a, b, HW2("punpckhbw"), v_unpack(a, b, 8, 1));
    CHECKV("punpcklwd", a, b, HW2("punpcklwd"), v_unpack(a, b, 16, 0));
    CHECKV("punpckhwd", a, b, HW2("punpckhwd"), v_unpack(a, b, 16, 1));
    CHECKV("punpckldq", a, b, HW2("punpckldq"), v_unpack(a, b, 32, 0));
    CHECKV("punpckhdq", a, b, HW2("punpckhdq"), v_unpack(a, b, 32, 1));
    CHECKV("punpcklqdq", a, b, HW2("punpcklqdq"), v_unpack(a, b, 64, 0));
    CHECKV("punpckhqdq", a, b, HW2("punpckhqdq"), v_unpack(a, b, 64, 1));
    CHECKV("unpcklpd", a, b, HW2("unpcklpd"), v_unpack(a, b, 64, 0));
    CHECKV("unpckhpd", a, b, HW2("unpckhpd"), v_unpack(a, b, 64, 1));
    CHECKV("unpcklps", a, b, HW2("unpcklps"), v_unpack(a, b, 32, 0));
    CHECKV("unpckhps", a, b, HW2("unpckhps"), v_unpack(a, b, 32, 1));
    CHECKV("addps", a, b, HW2("addps"), v_fp32(&G, a, b, SSE_ADD));
    CHECKV("subps", a, b, HW2("subps"), v_fp32(&G, a, b, SSE_SUB));
    CHECKV("mulps", a, b, HW2("mulps"), v_fp32(&G, a, b, SSE_MUL));
    CHECKV("divps", a, b, HW2("divps"), v_fp32(&G, a, b, SSE_DIV));
    CHECKV("addpd", a, b, HW2("addpd"), v_fp64(&G, a, b, SSE_ADD));
    CHECKV("subpd", a, b, HW2("subpd"), v_fp64(&G, a, b, SSE_SUB));
    CHECKV("mulpd", a, b, HW2("mulpd"), v_fp64(&G, a, b, SSE_MUL));
    CHECKV("divpd", a, b, HW2("divpd"), v_fp64(&G, a, b, SSE_DIV));
#define IMM(I) \
    CHECKV("pshufd" #I, a, b, HWI("pshufd $" #I), v_pshufd(b, I)); \
    CHECKV("pshuflw" #I, a, b, HWI("pshuflw $" #I), v_pshuflw(b, I)); \
    CHECKV("pshufhw" #I, a, b, HWI("pshufhw $" #I), v_pshufhw(b, I));
    IMM(0x00) IMM(0x1b) IMM(0x4e) IMM(0xb1) IMM(0xe4) IMM(0xff) IMM(0x8d)
#define SHUFPS(I) { v128 r_; __asm__ volatile("movdqu %1, %%xmm0; movdqu %2, %%xmm1; shufps $" #I ", %%xmm1, %%xmm0; movdqu %%xmm0, %0" \
                   : "=m"(r_) : "m"(a), "m"(b) : "xmm0", "xmm1"); CHECKV("shufps" #I, a, b, r_, v_shufps(a, b, I)); }
    SHUFPS(0x00) SHUFPS(0x1b) SHUFPS(0x44) SHUFPS(0xee) SHUFPS(0x88)
#define SHIMM(C) \
    CHECKV("psllw" #C, a, b, HWS("psllw $" #C), v_shift(a, C, 16, 0)); \
    CHECKV("pslld" #C, a, b, HWS("pslld $" #C), v_shift(a, C, 32, 0)); \
    CHECKV("psllq" #C, a, b, HWS("psllq $" #C), v_shift(a, C, 64, 0)); \
    CHECKV("psrlw" #C, a, b, HWS("psrlw $" #C), v_shift(a, C, 16, 1)); \
    CHECKV("psrld" #C, a, b, HWS("psrld $" #C), v_shift(a, C, 32, 1)); \
    CHECKV("psrlq" #C, a, b, HWS("psrlq $" #C), v_shift(a, C, 64, 1)); \
    CHECKV("psraw" #C, a, b, HWS("psraw $" #C), v_shift(a, C, 16, 2)); \
    CHECKV("psrad" #C, a, b, HWS("psrad $" #C), v_shift(a, C, 32, 2)); \
    CHECKV("pslldq" #C, a, b, HWS("pslldq $" #C), v_byteshift(a, C, 1)); \
    CHECKV("psrldq" #C, a, b, HWS("psrldq $" #C), v_byteshift(a, C, 0));
    SHIMM(0) SHIMM(1) SHIMM(3) SHIMM(7) SHIMM(8) SHIMM(15) SHIMM(16) SHIMM(31) SHIMM(32) SHIMM(63) SHIMM(64) SHIMM(200) SHIMM(255)
    /* shifts by an XMM count: the full low qword counts */
    static const uint64_t counts[] = { 0, 1, 5, 15, 16, 31, 32, 33, 63, 64, 65, 0x100000001ull, ~0ull };
    for (unsigned k = 0; k < sizeof counts / sizeof counts[0]; k++) {
        v128 cnt = { counts[k], rnd() };
        CHECKV("psllw_x", a, cnt, HWSH("psllw"), v_shift(a, counts[k], 16, 0));
        CHECKV("pslld_x", a, cnt, HWSH("pslld"), v_shift(a, counts[k], 32, 0));
        CHECKV("psllq_x", a, cnt, HWSH("psllq"), v_shift(a, counts[k], 64, 0));
        CHECKV("psrlw_x", a, cnt, HWSH("psrlw"), v_shift(a, counts[k], 16, 1));
        CHECKV("psrld_x", a, cnt, HWSH("psrld"), v_shift(a, counts[k], 32, 1));
        CHECKV("psrlq_x", a, cnt, HWSH("psrlq"), v_shift(a, counts[k], 64, 1));
        CHECKV("psraw_x", a, cnt, HWSH("psraw"), v_shift(a, counts[k], 16, 2));
        CHECKV("psrad_x", a, cnt, HWSH("psrad"), v_shift(a, counts[k], 32, 2));
    }
    /* masks */
    uint32_t m;
    __asm__ volatile("movdqu %1, %%xmm0; pmovmskb %%xmm0, %0" : "=r"(m) : "m"(a) : "xmm0");
    cases++; if (m != v_movmsk(a, 8)) report("pmovmskb", a, b, (v128){m, 0}, (v128){v_movmsk(a, 8), 0});
    __asm__ volatile("movdqu %1, %%xmm0; movmskps %%xmm0, %0" : "=r"(m) : "m"(a) : "xmm0");
    cases++; if (m != v_movmsk(a, 32)) report("movmskps", a, b, (v128){m, 0}, (v128){v_movmsk(a, 32), 0});
    __asm__ volatile("movdqu %1, %%xmm0; movmskpd %%xmm0, %0" : "=r"(m) : "m"(a) : "xmm0");
    cases++; if (m != v_movmsk(a, 64)) report("movmskpd", a, b, (v128){m, 0}, (v128){v_movmsk(a, 64), 0});
    /* CVTSI2SS from 64- and 32-bit sources */
    uint32_t f;
    __asm__ volatile("cvtsi2ssq %1, %%xmm0; movd %%xmm0, %0" : "=r"(f) : "r"(a.lo) : "xmm0");
    cases++; if (f != sse_cvtsi2ss(&G, a.lo, 64)) report("cvtsi2ss64", a, b, (v128){f, 0}, (v128){sse_cvtsi2ss(&G, a.lo, 64), 0});
    __asm__ volatile("cvtsi2ssl %k1, %%xmm0; movd %%xmm0, %0" : "=r"(f) : "r"(a.lo) : "xmm0");
    cases++; if (f != sse_cvtsi2ss(&G, a.lo, 32)) report("cvtsi2ss32", a, b, (v128){f, 0}, (v128){sse_cvtsi2ss(&G, a.lo, 32), 0});
}

int main(void) {
    for (int k = 0; k < 60000; k++) check(pickv(), pickv());
    /* cvtsi2ss edge cases around rounding boundaries of large integers */
    for (int k = 0; k < 64; k++)
        for (int d = -3; d <= 3; d++) {
            v128 a = { (1ull << k) + (uint64_t)(int64_t)d, 0 }, b = { 0, 0 };
            a.lo ^= (rnd() & 1) ? 0x8000000000000000ull : 0;
            check(a, b);
        }
    printf("simd differential cases=%ld failures=%ld\n", cases, failures);
    return failures ? 1 : 0;
}
#endif
