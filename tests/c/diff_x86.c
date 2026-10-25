/* Differential test: runtime/x86_cpu.h helpers vs. the real x86-64 CPU.
 *
 * TEST-ONLY ORACLE. This file executes native x86 instructions with inline
 * assembly to obtain reference results and RFLAGS. It is compiled only on an
 * x86-64 host and is never part of a translated program. Only flags that the
 * Intel SDM defines for each instruction are compared; undefined flags are
 * masked out.
 *
 * Build with -mno-red-zone (pushfq/popfq touch the stack below RSP).
 */
#if !defined(__x86_64__)
#include <stdio.h>
int main(void) { puts("SKIP: not an x86-64 host"); return 77; }
#else
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "runtime/x86_cpu.h"

#define F_CF (1u << 0)
#define F_PF (1u << 2)
#define F_AF (1u << 4)
#define F_ZF (1u << 6)
#define F_SF (1u << 7)
#define F_OF (1u << 11)
#define F_ALL (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next_rand(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

static const uint64_t special[] = {
    0, 1, 2, 3, 9, 10, 0x0f, 0x10, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
    0x7fffffff, 0x80000000, 0xffffffff, 0x100000000ull, 0x7fffffffffffffffull,
    0x8000000000000000ull, 0xfffffffffffffffeull, 0xffffffffffffffffull, 0xcccccccccccccccdull,
};
#define NSPECIAL (sizeof special / sizeof special[0])

static long cases, failures;

static uint64_t flags_of(const x86_state *s) {
    return (s->cf ? F_CF : 0) | (s->pf ? F_PF : 0) | (s->af ? F_AF : 0) |
           (s->zf ? F_ZF : 0) | (s->sf ? F_SF : 0) | (s->of ? F_OF : 0);
}
static void load_flags(x86_state *s, uint64_t f) {
    s->cf = !!(f & F_CF); s->pf = !!(f & F_PF); s->af = !!(f & F_AF);
    s->zf = !!(f & F_ZF); s->sf = !!(f & F_SF); s->of = !!(f & F_OF);
}

static void report(const char *op, unsigned bits, uint64_t a, uint64_t b, uint64_t fin,
                   uint64_t hr, uint64_t mr, uint64_t hf, uint64_t mf, uint64_t mask) {
    if (failures++ < 20)
        fprintf(stderr, "MISMATCH %s%u a=0x%" PRIx64 " b=0x%" PRIx64 " fin=0x%" PRIx64
                " hw=(0x%" PRIx64 ",fl 0x%" PRIx64 ") model=(0x%" PRIx64 ",fl 0x%" PRIx64 ") mask=0x%" PRIx64 "\n",
                op, bits, a, b, fin, hr, hf & mask, mr, mf & mask, mask);
}

/* ---- hardware reference implementations -------------------------------- */
#define HW_BIN(NAME, INSN)                                                              \
static uint64_t hw_##NAME(unsigned bits, uint64_t a, uint64_t b, uint64_t fin, uint64_t *fout) { \
    uint64_t x = a, f;                                                                  \
    switch (bits) {                                                                     \
    case 8:  __asm__ volatile("pushq %3; popfq; " INSN "b %b2, %b0; pushfq; popq %1"    \
                              : "+q"(x), "=r"(f) : "q"(b), "r"(fin) : "cc"); break;      \
    case 16: __asm__ volatile("pushq %3; popfq; " INSN "w %w2, %w0; pushfq; popq %1"    \
                              : "+r"(x), "=r"(f) : "r"(b), "r"(fin) : "cc"); break;      \
    case 32: __asm__ volatile("pushq %3; popfq; " INSN "l %k2, %k0; pushfq; popq %1"    \
                              : "+r"(x), "=r"(f) : "r"(b), "r"(fin) : "cc"); break;      \
    default: __asm__ volatile("pushq %3; popfq; " INSN "q %2, %0; pushfq; popq %1"      \
                              : "+r"(x), "=r"(f) : "r"(b), "r"(fin) : "cc"); break;      \
    }                                                                                   \
    *fout = f; return x & x86_mask(bits);                                               \
}
HW_BIN(add, "add")
HW_BIN(sub, "sub")
HW_BIN(and, "and")
HW_BIN(or, "or")
HW_BIN(xor, "xor")
HW_BIN(adc, "adc")
HW_BIN(sbb, "sbb")

#define HW_UN(NAME, INSN)                                                               \
static uint64_t hw_##NAME(unsigned bits, uint64_t a, uint64_t fin, uint64_t *fout) {   \
    uint64_t x = a, f;                                                                  \
    switch (bits) {                                                                     \
    case 8:  __asm__ volatile("pushq %2; popfq; " INSN "b %b0; pushfq; popq %1"         \
                              : "+q"(x), "=r"(f) : "r"(fin) : "cc"); break;              \
    case 16: __asm__ volatile("pushq %2; popfq; " INSN "w %w0; pushfq; popq %1"         \
                              : "+r"(x), "=r"(f) : "r"(fin) : "cc"); break;              \
    case 32: __asm__ volatile("pushq %2; popfq; " INSN "l %k0; pushfq; popq %1"         \
                              : "+r"(x), "=r"(f) : "r"(fin) : "cc"); break;              \
    default: __asm__ volatile("pushq %2; popfq; " INSN "q %0; pushfq; popq %1"          \
                              : "+r"(x), "=r"(f) : "r"(fin) : "cc"); break;              \
    }                                                                                   \
    *fout = f; return x & x86_mask(bits);                                               \
}
HW_UN(inc, "inc")
HW_UN(dec, "dec")
HW_UN(neg, "neg")
HW_UN(not, "not")

static uint64_t hw_shr(unsigned bits, uint64_t a, uint8_t c, uint64_t fin, uint64_t *fout) {
    uint64_t x = a, f;
    switch (bits) {
    case 8:  __asm__ volatile("pushq %3; popfq; shrb %%cl, %b0; pushfq; popq %1" : "+q"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break;
    case 16: __asm__ volatile("pushq %3; popfq; shrw %%cl, %w0; pushfq; popq %1" : "+r"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break;
    case 32: __asm__ volatile("pushq %3; popfq; shrl %%cl, %k0; pushfq; popq %1" : "+r"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break;
    default: __asm__ volatile("pushq %3; popfq; shrq %%cl, %0; pushfq; popq %1"  : "+r"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break;
    }
    *fout = f; return x & x86_mask(bits);
}

#define HW_SHIFT(NAME, INSN)                                                               \
static uint64_t hw_##NAME(unsigned bits, uint64_t a, uint8_t c, uint64_t fin, uint64_t *fout) { \
    uint64_t x = a, f;                                                                     \
    switch (bits) {                                                                        \
    case 8:  __asm__ volatile("pushq %3; popfq; " INSN "b %%cl, %b0; pushfq; popq %1" : "+q"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break; \
    case 16: __asm__ volatile("pushq %3; popfq; " INSN "w %%cl, %w0; pushfq; popq %1" : "+r"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break; \
    case 32: __asm__ volatile("pushq %3; popfq; " INSN "l %%cl, %k0; pushfq; popq %1" : "+r"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break; \
    default: __asm__ volatile("pushq %3; popfq; " INSN "q %%cl, %0; pushfq; popq %1"  : "+r"(x), "=r"(f) : "c"(c), "r"(fin) : "cc"); break; \
    }                                                                                      \
    *fout = f; return x & x86_mask(bits);                                                  \
}
HW_SHIFT(shl, "shl")
HW_SHIFT(sar, "sar")

static void hw_div(unsigned bits, uint64_t rax, uint64_t rdx, uint64_t src, uint64_t *orax, uint64_t *ordx) {
    uint64_t a = rax, d = rdx;
    if (bits == 64) __asm__ volatile("divq %2" : "+a"(a), "+d"(d) : "r"(src) : "cc");
    else            __asm__ volatile("divl %k2" : "+a"(a), "+d"(d) : "r"(src) : "cc");
    *orax = a; *ordx = d;
}

static uint64_t hw_bt(unsigned bits, uint64_t a, uint64_t b, uint64_t fin) {
    uint64_t f;
    switch (bits) {
    case 16: __asm__ volatile("pushq %3; popfq; btw %w2, %w1; pushfq; popq %0" : "=r"(f) : "r"(a), "r"(b), "r"(fin) : "cc"); break;
    case 32: __asm__ volatile("pushq %3; popfq; btl %k2, %k1; pushfq; popq %0" : "=r"(f) : "r"(a), "r"(b), "r"(fin) : "cc"); break;
    default: __asm__ volatile("pushq %3; popfq; btq %2, %1; pushfq; popq %0"   : "=r"(f) : "r"(a), "r"(b), "r"(fin) : "cc"); break;
    }
    return f;
}

static uint64_t hw_imul2(unsigned bits, uint64_t a, uint64_t b, uint64_t fin, uint64_t *fout) {
    uint64_t x = a, f;
    switch (bits) {
    case 16: __asm__ volatile("pushq %3; popfq; imulw %w2, %w0; pushfq; popq %1" : "+r"(x), "=r"(f) : "r"(b), "r"(fin) : "cc"); break;
    case 32: __asm__ volatile("pushq %3; popfq; imull %k2, %k0; pushfq; popq %1" : "+r"(x), "=r"(f) : "r"(b), "r"(fin) : "cc"); break;
    default: __asm__ volatile("pushq %3; popfq; imulq %2, %0; pushfq; popq %1"   : "+r"(x), "=r"(f) : "r"(b), "r"(fin) : "cc"); break;
    }
    *fout = f; return x & x86_mask(bits);
}

static void hw_mul(unsigned bits, uint64_t rax, uint64_t src, uint64_t *orax, uint64_t *ordx, uint64_t *fout) {
    uint64_t a = rax, d = 0x5555aaaa5555aaaaull, f;
    if (bits == 64)
        __asm__ volatile("mulq %3; pushfq; popq %2" : "+a"(a), "+d"(d), "=r"(f) : "r"(src) : "cc");
    else
        __asm__ volatile("mull %k3; pushfq; popq %2" : "+a"(a), "+d"(d), "=r"(f) : "r"(src) : "cc");
    *orax = a; *ordx = d; *fout = f;
}

static void hw_idiv(unsigned bits, uint64_t rax, uint64_t rdx, uint64_t src, uint64_t *orax, uint64_t *ordx) {
    uint64_t a = rax, d = rdx;
    if (bits == 64) __asm__ volatile("idivq %2" : "+a"(a), "+d"(d) : "r"(src) : "cc");
    else            __asm__ volatile("idivl %k2" : "+a"(a), "+d"(d) : "r"(src) : "cc");
    *orax = a; *ordx = d;
}

static int hw_cond(int cc, uint64_t fin) {
    uint8_t r;
#define SETCC(N, I) case N: __asm__ volatile("pushq %1; popfq; " I " %0" : "=q"(r) : "r"(fin) : "cc"); break;
    switch (cc) {
    SETCC(0, "seto") SETCC(1, "setno") SETCC(2, "setb") SETCC(3, "setae")
    SETCC(4, "sete") SETCC(5, "setne") SETCC(6, "setbe") SETCC(7, "seta")
    SETCC(8, "sets") SETCC(9, "setns") SETCC(10, "setp") SETCC(11, "setnp")
    SETCC(12, "setl") SETCC(13, "setge") SETCC(14, "setle") default: SETCC(15, "setg")
    }
#undef SETCC
    return r;
}

/* ---- comparison drivers ------------------------------------------------- */
static const unsigned widths[] = {8, 16, 32, 64};

static void cmp_result(const char *op, unsigned bits, uint64_t a, uint64_t b, uint64_t fin,
                       uint64_t hr, uint64_t hf, uint64_t mr, const x86_state *s, uint64_t mask) {
    cases++;
    uint64_t mf = flags_of(s);
    if (hr != mr || (hf & mask) != (mf & mask)) report(op, bits, a, b, fin, hr, mr, hf, mf, mask);
}

static void check_pair(uint64_t a, uint64_t b, uint64_t fin) {
    for (unsigned w = 0; w < 4; w++) {
        unsigned bits = widths[w];
        uint64_t m = x86_mask(bits), A = a & m, B = b & m, hf, hr, mr;
        x86_state s; memset(&s, 0, sizeof s);

#define BIN(NAME, MASK) load_flags(&s, fin); hr = hw_##NAME(bits, A, B, fin, &hf); \
        mr = x86_##NAME(&s, A, B, bits); cmp_result(#NAME, bits, A, B, fin, hr, hf, mr, &s, MASK);
        BIN(add, F_ALL)
        BIN(sub, F_ALL)
        BIN(and, F_CF | F_PF | F_ZF | F_SF | F_OF)
        BIN(or,  F_CF | F_PF | F_ZF | F_SF | F_OF)
        BIN(xor, F_CF | F_PF | F_ZF | F_SF | F_OF)
        BIN(adc, F_ALL)
        BIN(sbb, F_ALL)
#undef BIN
#define UN(NAME) load_flags(&s, fin); hr = hw_##NAME(bits, A, fin, &hf); \
        mr = x86_##NAME(&s, A, bits); cmp_result(#NAME, bits, A, 0, fin, hr, hf, mr, &s, F_ALL);
        UN(inc)
        UN(dec)
        UN(neg)
#undef UN
        /* NOT: result only; flags must be untouched (all 6 compared) */
        load_flags(&s, fin); hr = hw_not(bits, A, fin, &hf); mr = x86_not(A, bits);
        cmp_result("not", bits, A, 0, fin, hr, hf, mr, &s, F_ALL);
        /* SHR with every count 0..70 (exercises masking) */
        for (unsigned c = 0; c <= 70; c += (c < 10 ? 1 : 7)) {
            unsigned eff = c & (bits == 64 ? 0x3f : 0x1f);
            uint64_t mask = F_ALL;                         /* count 0: all unchanged */
            if (eff) {
                mask = F_PF | F_ZF | F_SF | F_CF;
                if (eff == 1) mask |= F_OF;
                if (eff >= bits) mask &= ~(uint64_t)F_CF;  /* CF undefined when count >= width */
            }
            load_flags(&s, fin);
            hr = hw_shr(bits, A, (uint8_t)c, fin, &hf);
            mr = x86_shr(&s, A, c, bits);
            cmp_result("shr", bits, A, c, fin, hr, hf, mr, &s, mask);
            /* SHL: same defined-flag rules as SHR (OF only for count 1) */
            load_flags(&s, fin);
            hr = hw_shl(bits, A, (uint8_t)c, fin, &hf);
            mr = x86_shl(&s, A, c, bits);
            cmp_result("shl", bits, A, c, fin, hr, hf, mr, &s, mask);
            /* SAR */
            load_flags(&s, fin);
            hr = hw_sar(bits, A, (uint8_t)c, fin, &hf);
            mr = x86_sar(&s, A, c, bits);
            cmp_result("sar", bits, A, c, fin, hr, hf, mr, &s, mask);
        }
        if (bits >= 16) {
            /* BT reg, reg: CF from the selected bit, ZF must be unchanged */
            load_flags(&s, fin);
            hf = hw_bt(bits, A, B, fin);
            x86_bt(&s, A, B, bits);
            cmp_result("bt", bits, A, B, fin, 0, hf, 0, &s, F_CF | F_ZF);
            load_flags(&s, fin);
            hr = hw_imul2(bits, A, B, fin, &hf);
            mr = x86_imul2(&s, A, B, bits);
            cmp_result("imul2_", bits, A, B, fin, hr, hf, mr, &s, F_CF | F_OF);
        }
        if (bits >= 32) {
            uint64_t orax, ordx;
            load_flags(&s, fin);
            s.gpr[X86_RAX] = a; s.gpr[X86_RDX] = 0x5555aaaa5555aaaaull;
            hw_mul(bits, a, b, &orax, &ordx, &hf);
            x86_mul(&s, b, bits);
            cases++;
            if (orax != s.gpr[X86_RAX] || ordx != s.gpr[X86_RDX] || (hf & (F_CF | F_OF)) != (flags_of(&s) & (F_CF | F_OF)))
                report("mul", bits, a, b, fin, orax, s.gpr[X86_RAX], hf, flags_of(&s), F_CF | F_OF);

            /* IDIV: only inputs that do not raise #DE on hardware */
            uint64_t rdx_in = (next_rand() & 1) ? ((a >> 63) ? ~0ull : 0) : (next_rand() & 0xff);
            if (bits == 32) rdx_in &= 0xffffffffu;
            int ok = 0;
            if (bits == 32) {
                int64_t dividend = (int64_t)(((rdx_in & 0xffffffffu) << 32) | (a & 0xffffffffu));
                int64_t divisor = (int64_t)x86_sext(b, 32);
                if (divisor != 0 && !(divisor == -1 && dividend == INT64_MIN)) {
                    int64_t q = dividend / divisor;
                    ok = q >= INT32_MIN && q <= INT32_MAX;
                }
            } else {
                __int128 dividend = (__int128)(((unsigned __int128)rdx_in << 64) | a);
                __int128 divisor = (__int128)(int64_t)b;
                if (divisor != 0 && !(divisor == -1 && rdx_in == 0x8000000000000000ull && a == 0)) {
                    __int128 q = dividend / divisor;
                    ok = q >= INT64_MIN && q <= INT64_MAX;
                }
            }
            if (ok) {
                hw_idiv(bits, a, rdx_in, b, &orax, &ordx);
                s.gpr[X86_RAX] = a; s.gpr[X86_RDX] = rdx_in;
                x86_idiv(&s, b, bits);
                cases++;
                if (orax != s.gpr[X86_RAX] || ordx != s.gpr[X86_RDX])
                    report("idiv", bits, a, b, rdx_in, orax, s.gpr[X86_RAX], ordx, s.gpr[X86_RDX], 0);
            }
            /* DIV (unsigned): only inputs that do not raise #DE */
            {
                uint64_t rdx_u = next_rand();
                if (next_rand() & 1) rdx_u = 0;
                uint64_t div_b = b, ok_u;
                if (bits == 32) { rdx_u &= 0xffffffffu; div_b &= 0xffffffffu;
                    ok_u = div_b != 0 && (((rdx_u << 32) | (a & 0xffffffffu)) / div_b) <= 0xffffffffu; }
                else ok_u = div_b != 0 && rdx_u < div_b;
                if (ok_u) {
                    hw_div(bits, a, rdx_u, b, &orax, &ordx);
                    s.gpr[X86_RAX] = a; s.gpr[X86_RDX] = rdx_u;
                    x86_div(&s, b, bits);
                    cases++;
                    if (orax != s.gpr[X86_RAX] || ordx != s.gpr[X86_RDX])
                        report("div", bits, a, b, rdx_u, orax, s.gpr[X86_RAX], ordx, s.gpr[X86_RDX], 0);
                }
            }
            /* CDQE / CWDE */
            {
                uint64_t ra = a;
                if (bits == 32) { __asm__ volatile("cltq" : "+a"(ra)); s.gpr[X86_RAX] = a; x86_cdqe(&s); }
                else            { __asm__ volatile("cwtl" : "+a"(ra)); s.gpr[X86_RAX] = a; x86_cwde(&s); }
                cases++;
                if (ra != s.gpr[X86_RAX]) report(bits == 32 ? "cdqe" : "cwde", bits, a, 0, 0, ra, s.gpr[X86_RAX], 0, 0, 0);
            }
            /* CDQ / CQO */
            uint64_t ca = a, cd = 0x1234567812345678ull;
            if (bits == 32) __asm__ volatile("cltd" : "+a"(ca), "+d"(cd));
            else            __asm__ volatile("cqto" : "+a"(ca), "+d"(cd));
            s.gpr[X86_RAX] = a; s.gpr[X86_RDX] = 0x1234567812345678ull;
            if (bits == 32) x86_cdq(&s); else x86_cqo(&s);
            cases++;
            if (cd != s.gpr[X86_RDX]) report(bits == 32 ? "cdq" : "cqo", bits, a, 0, 0, cd, s.gpr[X86_RDX], 0, 0, 0);
        }
    }
}

int main(void) {
    for (unsigned i = 0; i < NSPECIAL; i++)
        for (unsigned j = 0; j < NSPECIAL; j++)
            check_pair(special[i], special[j], next_rand() & F_ALL);
    for (int k = 0; k < 20000; k++) {
        uint64_t a = next_rand(), b = next_rand();
        if (k & 1) b >>= (next_rand() & 63);           /* vary magnitudes */
        if (k & 2) a >>= (next_rand() & 63);
        check_pair(a, b, next_rand() & F_ALL);
    }
    /* all 16 conditions against every combination of the 6 status flags */
    for (uint64_t combo = 0; combo < 64; combo++) {
        uint64_t fin = ((combo & 1) ? F_CF : 0) | ((combo & 2) ? F_PF : 0) | ((combo & 4) ? F_AF : 0) |
                       ((combo & 8) ? F_ZF : 0) | ((combo & 16) ? F_SF : 0) | ((combo & 32) ? F_OF : 0);
        x86_state s; memset(&s, 0, sizeof s);
        load_flags(&s, fin);
        for (int cc = 0; cc < 16; cc++) {
            cases++;
            if (!!x86_cond(&s, cc) != hw_cond(cc, fin)) report("cond", (unsigned)cc, fin, 0, fin, hw_cond(cc, fin), x86_cond(&s, cc), 0, 0, 0);
        }
    }
    printf("differential cases=%ld failures=%ld\n", cases, failures);
    return failures ? 1 : 0;
}
#endif
