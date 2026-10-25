/* exe2mac scalar SSE/SSE2 semantics.
 *
 * Values are carried as raw bits (uint64_t for double, uint32_t for float).
 * Arithmetic on non-NaN inputs uses the host's IEEE-754 binary64/binary32
 * operations, which are correctly rounded on both x86-64 SSE and ARM64 under
 * the default environment (round-to-nearest-even, no flush-to-zero /
 * denormals-are-zero). That matches the Windows x64 default MXCSR (0x1F80).
 * Generated code must be compiled with -ffp-contract=off so the host compiler
 * never fuses a multiply and an add.
 *
 * NaN results follow the x86 rules (Intel SDM Vol. 1, Table 4-7) explicitly,
 * because ARM64 propagates and generates NaNs differently:
 *   - first source is NaN  -> first source, quieted
 *   - else second is NaN   -> second source, quieted
 *   - invalid operation    -> "QNaN floating-point indefinite"
 *                             (0xFFF8000000000000 / 0xFFC00000, sign bit SET)
 * MXCSR exception flags are not modelled; all exceptions are masked (default).
 */
#ifndef EXE2MAC_X86_SSE_H
#define EXE2MAC_X86_SSE_H

#include <stdint.h>
/* Only compiler builtins (no libc headers), so generated code stays
 * freestanding-compilable for any target. __builtin_sqrt lowers to the
 * correctly rounded hardware instruction (sqrtsd on x86-64, fsqrt on ARM64). */

#include "x86_cpu.h"

#define F64_INDEFINITE 0xFFF8000000000000ull
#define F32_INDEFINITE 0xFFC00000u
#define F64_QUIET_BIT  0x0008000000000000ull
#define F32_QUIET_BIT  0x00400000u
#define I32_INDEFINITE 0x80000000u
#define I64_INDEFINITE 0x8000000000000000ull

static inline double f64_of(uint64_t b) { double d; __builtin_memcpy(&d, &b, 8); return d; }
static inline uint64_t f64_bits(double d) { uint64_t b; __builtin_memcpy(&b, &d, 8); return b; }
static inline float f32_of(uint32_t b) { float f; __builtin_memcpy(&f, &b, 4); return f; }
static inline uint32_t f32_bits(float f) { uint32_t b; __builtin_memcpy(&b, &f, 4); return b; }

static inline int f64_isnan(uint64_t b) { return (b & 0x7FF0000000000000ull) == 0x7FF0000000000000ull && (b & 0x000FFFFFFFFFFFFFull); }
static inline int f32_isnan(uint32_t b) { return (b & 0x7F800000u) == 0x7F800000u && (b & 0x007FFFFFu); }

enum { SSE_ADD, SSE_SUB, SSE_MUL, SSE_DIV };

static inline uint64_t sse_f64_arith(uint64_t a, uint64_t b, int op) {
    if (f64_isnan(a)) return a | F64_QUIET_BIT;
    if (f64_isnan(b)) return b | F64_QUIET_BIT;
    double x = f64_of(a), y = f64_of(b), r;
    switch (op) {
    case SSE_ADD: r = x + y; break;
    case SSE_SUB: r = x - y; break;
    case SSE_MUL: r = x * y; break;
    default:      r = x / y; break;
    }
    uint64_t rb = f64_bits(r);
    return f64_isnan(rb) ? F64_INDEFINITE : rb;      /* invalid: inf-inf, 0*inf, 0/0, inf/inf */
}

static inline uint32_t sse_f32_arith(uint32_t a, uint32_t b, int op) {
    if (f32_isnan(a)) return a | F32_QUIET_BIT;
    if (f32_isnan(b)) return b | F32_QUIET_BIT;
    float x = f32_of(a), y = f32_of(b), r;
    switch (op) {
    case SSE_ADD: r = x + y; break;
    case SSE_SUB: r = x - y; break;
    case SSE_MUL: r = x * y; break;
    default:      r = x / y; break;
    }
    uint32_t rb = f32_bits(r);
    return f32_isnan(rb) ? F32_INDEFINITE : rb;
}

static inline uint64_t sse_f64_sqrt(uint64_t b) {
    if (f64_isnan(b)) return b | F64_QUIET_BIT;
    uint64_t rb = f64_bits(__builtin_sqrt(f64_of(b)));          /* sqrt(-0) = -0 per IEEE */
    return f64_isnan(rb) ? F64_INDEFINITE : rb;
}

/* MAXSD/MINSD: dest = (a OP b) ? a : b. Any NaN or (+0,-0) pair returns the
 * SECOND operand unchanged (not quieted) - exactly this C expression. */
static inline uint64_t sse_f64_max(uint64_t a, uint64_t b) { return f64_of(a) > f64_of(b) ? a : b; }
static inline uint64_t sse_f64_min(uint64_t a, uint64_t b) { return f64_of(a) < f64_of(b) ? a : b; }

/* UCOMISD/COMISD: ZF,PF,CF = 111 unordered, 000 greater, 001 less, 100 equal;
 * OF=SF=AF=0. (COMISD differs only in signalling QNaN, which is masked.) */
static inline void sse_f64_ucomi(x86_state *s, uint64_t a, uint64_t b) {
    s->of = s->sf = s->af = 0;
    if (f64_isnan(a) || f64_isnan(b)) { s->zf = s->pf = s->cf = 1; return; }
    double x = f64_of(a), y = f64_of(b);
    s->pf = 0;
    s->zf = x == y;
    s->cf = x < y;
}

/* CMPSD predicate imm8[2:0]: EQ LT LE UNORD NEQ NLT NLE ORD -> all-ones/zeros mask. */
static inline uint64_t sse_f64_cmp(uint64_t a, uint64_t b, unsigned pred) {
    int un = f64_isnan(a) || f64_isnan(b);
    double x = f64_of(a), y = f64_of(b);
    int r;
    switch (pred & 7) {
    case 0: r = !un && x == y; break;
    case 1: r = !un && x < y; break;
    case 2: r = !un && x <= y; break;
    case 3: r = un; break;
    case 4: r = un || x != y; break;
    case 5: r = un || !(x < y); break;
    case 6: r = un || !(x <= y); break;
    default: r = !un; break;
    }
    return r ? ~(uint64_t)0 : 0;
}

/* CVTTSD2SI: truncate; NaN or out of range -> integer indefinite. */
static inline uint64_t sse_cvttsd2si(uint64_t b, unsigned bits) {
    if (f64_isnan(b)) return bits == 64 ? I64_INDEFINITE : I32_INDEFINITE;
    double x = f64_of(b);
    if (bits == 64) {
        /* trunc(x) fits in int64 iff -2^63 <= x < 2^63 (no double lies strictly
         * between -2^63-1 and -2^63, both bounds are exact doubles). */
        if (!(x >= -9223372036854775808.0 && x < 9223372036854775808.0)) return I64_INDEFINITE;
        return (uint64_t)(int64_t)x;                   /* in range: C truncation is defined */
    }
    if (!(x > -2147483649.0 && x < 2147483648.0)) return I32_INDEFINITE;
    return (uint32_t)(int32_t)x;
}

/* CVTSI2SD: signed integer -> double, rounded to nearest-even (exact for 32-bit). */
static inline uint64_t sse_cvtsi2sd(uint64_t v, unsigned bits) {
    int64_t i = (int64_t)x86_sext(v, bits);
    return f64_bits((double)i);
}

/* CVTSD2SS / CVTSS2SD with explicit NaN handling (sign kept, payload
 * truncated/extended, quiet bit set) - identical on every host. */
static inline uint32_t sse_cvtsd2ss(uint64_t b) {
    if (f64_isnan(b))
        return (uint32_t)((b >> 32) & 0x80000000u) | 0x7FC00000u | (uint32_t)((b >> 29) & 0x003FFFFFu);
    return f32_bits((float)f64_of(b));                 /* RN; overflow -> inf; gradual underflow */
}
static inline uint64_t sse_cvtss2sd(uint32_t b) {
    if (f32_isnan(b))
        return ((uint64_t)(b & 0x80000000u) << 32) | 0x7FF8000000000000ull | ((uint64_t)(b & 0x003FFFFFu) << 29);
    return f64_bits((double)f32_of(b));                /* exact */
}

/* 128-bit register helpers */
static inline void xmm_set_lo64_zero_hi(x86_state *s, int x, uint64_t v) { s->xmm[x].lo = v; s->xmm[x].hi = 0; }
static inline void xmm_set_lo64(x86_state *s, int x, uint64_t v) { s->xmm[x].lo = v; }
static inline void xmm_set_lo32(x86_state *s, int x, uint32_t v) {
    s->xmm[x].lo = (s->xmm[x].lo & 0xFFFFFFFF00000000ull) | v;
}
static inline void xmm_set_lo32_zero_rest(x86_state *s, int x, uint32_t v) { s->xmm[x].lo = v; s->xmm[x].hi = 0; }

/* Aligned 128-bit memory operand for legacy-SSE packed instructions. */
static inline void sse_ld128(x86_state *s, uint64_t va, int aligned, uint64_t *lo, uint64_t *hi) {
    if (aligned && (va & 15))
        exe2mac_raise(s, EXE2MAC_STATUS_ACCESS_VIOLATION_CODE, "SSE: misaligned 128-bit operand");
    (void)guest_ptr(s->mem, va, 16, GUEST_PERM_R);
    *lo = guest_ld64(s->mem, va);
    *hi = guest_ld64(s->mem, va + 8);
}

#endif
