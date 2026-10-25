/* exe2mac scalar SSE/SSE2 semantics with a modelled MXCSR.
 *
 * All floating-point arithmetic goes through runtime/softfloat.h: results are
 * computed exactly in integers and rounded once according to MXCSR.RC, with
 * FTZ / DAZ and the six sticky exception flags exactly as x86 SSE does
 * (verified against hardware in all 16 RC x FTZ x DAZ settings). The host FPU
 * is never used for guest arithmetic, so ARM64 hosts produce identical bits
 * and flags (NaN encodings, underflow detection, signed zeros).
 *
 * Exception flags are ORed into x86_state.mxcsr. An exception whose mask bit
 * is clear raises an SSE floating-point exception (#XM). There is no SEH, so
 * it ends the process with the Windows status code (see sse_flags()).
 */
#ifndef EXE2MAC_X86_SSE_H
#define EXE2MAC_X86_SSE_H

#include <stdint.h>
/* Only compiler builtins (no libc headers), so generated code stays
 * freestanding-compilable for any target. __builtin_sqrt lowers to the
 * correctly rounded hardware instruction (sqrtsd on x86-64, fsqrt on ARM64). */

#include "softfloat.h"
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

#define EXE2MAC_MXCSR_DEFAULT                0x1F80u
/* NTSTATUS for an unhandled SSE floating-point exception (#XM). Windows
 * reports the specific cause; with several unmasked causes the first in the
 * order IE, DE, ZE, OE, UE, PE is used (verified on Windows, see test/xm.c). */
#define EXE2MAC_STATUS_FLOAT_INVALID_OPERATION 0xC0000090u
#define EXE2MAC_STATUS_FLOAT_DENORMAL_OPERAND  0xC000008Du
#define EXE2MAC_STATUS_FLOAT_DIVIDE_BY_ZERO    0xC000008Eu
#define EXE2MAC_STATUS_FLOAT_OVERFLOW          0xC0000091u
#define EXE2MAC_STATUS_FLOAT_UNDERFLOW         0xC0000093u
#define EXE2MAC_STATUS_FLOAT_INEXACT_RESULT    0xC000008Fu

static inline sf_env sse_env(const x86_state *s) { return sf_env_of(s->mxcsr); }

/* Record exception flags; raise #XM for any unmasked one.
 * `fl` holds every flag the operation (all lanes) would raise if nothing
 * faulted. When an exception is unmasked, x86 stops early (SDM Vol.1 11.5.1,
 * checked against hardware by tests/c/diff_xm.c):
 *   an unmasked pre-computation exception (IE, DE, ZE) faults before the
 *   result is computed, so only the pre-computation flags are recorded.
 * (PE under an unmasked OE/UE is decided in sf_round_pack.) */
static inline void sse_flags(x86_state *s, unsigned fl) {
    unsigned um = ~(s->mxcsr >> 7) & 0x3fu;
    if (fl & um & 0x07u) fl &= 0x07u;
    s->mxcsr |= fl & 0x3fu;
    unsigned unmasked = fl & um;
    if (unmasked) {
        static const uint32_t status[6] = {
            /* Windows reports an SSE denormal-operand fault as INVALID_OPERATION
             * (observed: test/xm.exe case 1 -> 0xC0000090 on Windows CI) */
            EXE2MAC_STATUS_FLOAT_INVALID_OPERATION, EXE2MAC_STATUS_FLOAT_INVALID_OPERATION,
            EXE2MAC_STATUS_FLOAT_DIVIDE_BY_ZERO, EXE2MAC_STATUS_FLOAT_OVERFLOW,
            EXE2MAC_STATUS_FLOAT_UNDERFLOW, EXE2MAC_STATUS_FLOAT_INEXACT_RESULT };
        unsigned i = 0;
        while (!(unmasked & (1u << i))) i++;
        exe2mac_raise(s, status[i], "unmasked SSE floating-point exception");
    }
}

static inline uint64_t sf_arith(const sf_fmt *f, const sf_env *e, uint64_t a, uint64_t b, int op, unsigned *fl) {
    switch (op) {
    case SSE_ADD: return sf_add(f, e, a, b, 0, fl);
    case SSE_SUB: return sf_add(f, e, a, b, 1, fl);
    case SSE_MUL: return sf_mul(f, e, a, b, fl);
    default:      return sf_div(f, e, a, b, fl);
    }
}
static inline uint64_t sse_f64_arith(x86_state *s, uint64_t a, uint64_t b, int op) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint64_t r = sf_arith(&SF_F64, &e, a, b, op, &fl);
    sse_flags(s, fl);
    return r;
}
static inline uint32_t sse_f32_arith(x86_state *s, uint32_t a, uint32_t b, int op) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint32_t r = (uint32_t)sf_arith(&SF_F32, &e, a, b, op, &fl);
    sse_flags(s, fl);
    return r;
}
static inline uint64_t sse_f64_sqrt(x86_state *s, uint64_t b) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint64_t r = sf_sqrt(&SF_F64, &e, b, &fl);
    sse_flags(s, fl);
    return r;
}
static inline uint32_t sse_f32_sqrt(x86_state *s, uint32_t b) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint32_t r = (uint32_t)sf_sqrt(&SF_F32, &e, b, &fl);
    sse_flags(s, fl);
    return r;
}

/* Pre-computation flags shared by compare-type instructions:
 * IE for SNaN (or for any NaN when `signalling`), DE for a denormal source
 * that is not flushed by DAZ when no NaN is involved. */
static inline unsigned sse_cmp_flags(const sf_env *e, const sf_num *a, const sf_num *b, int signalling) {
    unsigned fl = 0;
    int qn = a->cls == SF_QNAN || b->cls == SF_QNAN, sn = a->cls == SF_SNAN || b->cls == SF_SNAN;
    if (sn || (signalling && qn)) fl |= SF_IE;
    if (!sn && !qn && !e->daz && (a->denormal || b->denormal)) fl |= SF_DE;
    return fl;
}

/* MAXSD/MINSD (and SS): dst = (a OP b) ? a : b after DAZ; any NaN or a
 * (+0, -0) pair returns the SECOND operand. IE for any NaN. */
static inline uint64_t sse_minmax(x86_state *s, const sf_fmt *f, uint64_t a, uint64_t b, int want_max) {
    sf_env e = sse_env(s);
    sf_num x = sf_unpack(f, a, &e), y = sf_unpack(f, b, &e);
    sse_flags(s, sse_cmp_flags(&e, &x, &y, 1));
    int c = sf_compare(f, &x, &y);
    uint64_t pick = (c != 2 && (want_max ? c > 0 : c < 0)) ? a : b;
    /* x86: a denormal flushed by DAZ is returned as a signed zero */
    sf_num chosen = pick == a ? x : y;
    if (e.daz && chosen.denormal) return sf_zero(f, chosen.sign);
    return pick;
}
static inline uint32_t sse_f32_max(x86_state *s, uint32_t a, uint32_t b) { return (uint32_t)sse_minmax(s, &SF_F32, a, b, 1); }
static inline uint32_t sse_f32_min(x86_state *s, uint32_t a, uint32_t b) { return (uint32_t)sse_minmax(s, &SF_F32, a, b, 0); }
static inline uint64_t sse_f64_max(x86_state *s, uint64_t a, uint64_t b) { return sse_minmax(s, &SF_F64, a, b, 1); }
static inline uint64_t sse_f64_min(x86_state *s, uint64_t a, uint64_t b) { return sse_minmax(s, &SF_F64, a, b, 0); }

/* UCOMISD/COMISD: ZF,PF,CF = 111 unordered, 000 greater, 001 less, 100 equal;
 * OF=SF=AF=0. UCOMISD signals IE only for SNaN, COMISD for any NaN. */
static inline void sse_ucomi(x86_state *s, const sf_fmt *f, uint64_t a, uint64_t b, int signalling) {
    sf_env e = sse_env(s);
    sf_num x = sf_unpack(f, a, &e), y = sf_unpack(f, b, &e);
    sse_flags(s, sse_cmp_flags(&e, &x, &y, signalling));
    int c = sf_compare(f, &x, &y);
    s->of = s->sf = s->af = 0;
    s->zf = c == 0 || c == 2;
    s->pf = c == 2;
    s->cf = c < 0 || c == 2;
}
static inline void sse_f32_ucomi(x86_state *s, uint32_t a, uint32_t b) { sse_ucomi(s, &SF_F32, a, b, 0); }
static inline void sse_f32_comi(x86_state *s, uint32_t a, uint32_t b) { sse_ucomi(s, &SF_F32, a, b, 1); }
static inline void sse_f64_ucomi(x86_state *s, uint64_t a, uint64_t b) { sse_ucomi(s, &SF_F64, a, b, 0); }
static inline void sse_f64_comi(x86_state *s, uint64_t a, uint64_t b) { sse_ucomi(s, &SF_F64, a, b, 1); }

/* CMPSD predicate imm8[2:0]: EQ LT LE UNORD NEQ NLT NLE ORD -> all-ones/zeros mask.
 * LT/LE/NLT/NLE signal IE on any NaN; the others only on SNaN. */
static inline int sse_cmp_pred(int c, unsigned p);
static inline uint64_t sse_cmp_fmt(x86_state *s, const sf_fmt *f, uint64_t a, uint64_t b, unsigned pred) {
    sf_env e = sse_env(s);
    sf_num x = sf_unpack(f, a, &e), y = sf_unpack(f, b, &e);
    unsigned p = pred & 7;
    sse_flags(s, sse_cmp_flags(&e, &x, &y, p == 1 || p == 2 || p == 5 || p == 6));
    return sse_cmp_pred(sf_compare(f, &x, &y), p) ? (f == &SF_F64 ? ~(uint64_t)0 : 0xffffffffu) : 0;
}
static inline uint32_t sse_f32_cmp(x86_state *s, uint32_t a, uint32_t b, unsigned pred) {
    return (uint32_t)sse_cmp_fmt(s, &SF_F32, a, b, pred);
}
static inline int sse_cmp_pred(int c, unsigned p) {
    int un = c == 2;
    switch (p & 7) {
    case 0: return c == 0;
    case 1: return !un && c < 0;
    case 2: return !un && c <= 0;
    case 3: return un;
    case 4: return c != 0;
    case 5: return un || c >= 0;
    case 6: return un || c > 0;
    default: return !un;
    }
}
static inline uint64_t sse_f64_cmp(x86_state *s, uint64_t a, uint64_t b, unsigned pred) {
    sf_env e = sse_env(s);
    sf_num x = sf_unpack(&SF_F64, a, &e), y = sf_unpack(&SF_F64, b, &e);
    unsigned p = pred & 7;
    sse_flags(s, sse_cmp_flags(&e, &x, &y, p == 1 || p == 2 || p == 5 || p == 6));
    int c = sf_compare(&SF_F64, &x, &y), un = c == 2, r;
    switch (p) {
    case 0: r = c == 0; break;
    case 1: r = !un && c < 0; break;
    case 2: r = !un && c <= 0; break;
    case 3: r = un; break;
    case 4: r = c != 0; break;
    case 5: r = un || c >= 0; break;
    case 6: r = un || c > 0; break;
    default: r = !un; break;
    }
    return r ? ~(uint64_t)0 : 0;
}

/* Conversions */
static inline uint64_t sse_to_int(x86_state *s, const sf_fmt *f, uint64_t b, unsigned bits, int truncate) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint64_t r = sf_to_int(f, &e, b, bits, truncate, &fl);
    sse_flags(s, fl);
    return r;
}
static inline uint64_t sse_cvttsd2si(x86_state *s, uint64_t b, unsigned bits) { return sse_to_int(s, &SF_F64, b, bits, 1); }
static inline uint64_t sse_cvtsd2si(x86_state *s, uint64_t b, unsigned bits) { return sse_to_int(s, &SF_F64, b, bits, 0); }
static inline uint64_t sse_cvttss2si(x86_state *s, uint32_t b, unsigned bits) { return sse_to_int(s, &SF_F32, b, bits, 1); }
static inline uint64_t sse_cvtss2si(x86_state *s, uint32_t b, unsigned bits) { return sse_to_int(s, &SF_F32, b, bits, 0); }
static inline uint64_t sse_cvtsi2sd(x86_state *s, uint64_t v, unsigned bits) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint64_t r = sf_from_int(&SF_F64, &e, (int64_t)x86_sext(v, bits), &fl);
    sse_flags(s, fl);
    return r;
}
static inline uint32_t sse_cvtsi2ss(x86_state *s, uint64_t v, unsigned bits) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint32_t r = (uint32_t)sf_from_int(&SF_F32, &e, (int64_t)x86_sext(v, bits), &fl);
    sse_flags(s, fl);
    return r;
}
static inline uint32_t sse_cvtsd2ss(x86_state *s, uint64_t b) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint32_t r = sf_f64_to_f32(&e, b, &fl);
    sse_flags(s, fl);
    return r;
}
static inline uint64_t sse_cvtss2sd(x86_state *s, uint32_t b) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint64_t r = sf_f32_to_f64(&e, b, &fl);
    sse_flags(s, fl);
    return r;
}

/* LDMXCSR / STMXCSR. Bits 16..31 are reserved: setting one is #GP. */
static inline void sse_ldmxcsr(x86_state *s, uint32_t v) {
    if (v & 0xFFFF0000u) exe2mac_raise(s, EXE2MAC_STATUS_ACCESS_VIOLATION_CODE, "ldmxcsr: reserved MXCSR bit set");
    s->mxcsr = v;
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
