/* exe2mac soft-float: IEEE-754 binary64 / binary32 arithmetic with x86 SSE
 * MXCSR semantics (rounding control, FTZ, DAZ, sticky exception flags).
 *
 * Written for exe2mac (no code taken from Berkeley SoftFloat or others).
 * Every operation is computed exactly in integers (unsigned __int128) and
 * rounded once, so results and flags do not depend on the host FPU, its
 * rounding mode, its NaN conventions or its underflow (tininess) rule.
 * x86-specific choices are marked "x86:" and are verified against real SSE
 * hardware by tests/c/diff_mxcsr.c across all 16 RC x FTZ x DAZ settings.
 *
 * Values are passed as raw bits. Every function ORs the exception flags it
 * raises into *flags (MXCSR bit layout: IE DE ZE OE UE PE = bits 0..5).
 */
#ifndef EXE2MAC_SOFTFLOAT_H
#define EXE2MAC_SOFTFLOAT_H

#include <stdint.h>

#define SF_IE 0x01u
#define SF_DE 0x02u
#define SF_ZE 0x04u
#define SF_OE 0x08u
#define SF_UE 0x10u
#define SF_PE 0x20u

#define SF_RN 0
#define SF_RD 1
#define SF_RU 2
#define SF_RZ 3

typedef unsigned __int128 sf_u128;

typedef struct sf_fmt {
    unsigned p;           /* precision incl. implicit bit: 53 / 24 */
    unsigned ebits;       /* exponent field width: 11 / 8 */
    int bias, emin, emax;
} sf_fmt;
static const sf_fmt SF_F64 = { 53, 11, 1023, -1022, 1023 };
static const sf_fmt SF_F32 = { 24, 8, 127, -126, 127 };

/* MXCSR environment for one operation */
typedef struct sf_env { unsigned rc, ftz, daz; } sf_env;
static inline sf_env sf_env_of(uint32_t mxcsr) {
    sf_env e = { (mxcsr >> 13) & 3u, (mxcsr >> 15) & 1u, (mxcsr >> 6) & 1u };
    return e;
}

enum { SF_ZERO, SF_FINITE, SF_INF, SF_QNAN, SF_SNAN };

typedef struct sf_num {
    int cls;
    unsigned sign;
    int exp;              /* value = sig * 2^(exp - (p-1)), sig normalised (bit p-1 set) */
    uint64_t sig;
    int denormal;         /* input was a denormal (before DAZ) */
    uint64_t bits;
} sf_num;

static inline uint64_t sf_fracmask(const sf_fmt *f) { return (1ull << (f->p - 1)) - 1; }
static inline uint64_t sf_signbit(const sf_fmt *f) { return 1ull << (f->p - 1 + f->ebits); }
static inline uint64_t sf_quietbit(const sf_fmt *f) { return 1ull << (f->p - 2); }
static inline uint64_t sf_inf(const sf_fmt *f, unsigned sign) {
    return (sign ? sf_signbit(f) : 0) | ((((uint64_t)1 << f->ebits) - 1) << (f->p - 1));
}
static inline uint64_t sf_max(const sf_fmt *f, unsigned sign) { return sf_inf(f, sign) - 1; }
static inline uint64_t sf_zero(const sf_fmt *f, unsigned sign) { return sign ? sf_signbit(f) : 0; }
/* x86 "QNaN floating-point indefinite": sign set, quiet bit set, payload 0 */
static inline uint64_t sf_indefinite(const sf_fmt *f) { return sf_inf(f, 1) | sf_quietbit(f); }

static inline sf_num sf_unpack(const sf_fmt *f, uint64_t bits, const sf_env *env) {
    sf_num n;
    unsigned emax_field = (1u << f->ebits) - 1;
    n.bits = bits;
    n.sign = (unsigned)((bits >> (f->p - 1 + f->ebits)) & 1);
    unsigned E = (unsigned)((bits >> (f->p - 1)) & emax_field);
    uint64_t F = bits & sf_fracmask(f);
    n.denormal = 0;
    n.exp = 0;
    n.sig = 0;
    if (E == emax_field) {
        n.cls = F == 0 ? SF_INF : (F & sf_quietbit(f)) ? SF_QNAN : SF_SNAN;
    } else if (E == 0) {
        if (F == 0) {
            n.cls = SF_ZERO;
        } else {
            n.denormal = 1;
            if (env->daz) {                 /* x86: DAZ turns a denormal source into a signed zero */
                n.cls = SF_ZERO;
            } else {
                n.cls = SF_FINITE;
                n.sig = F;
                n.exp = f->emin;
                while (!(n.sig >> (f->p - 1))) { n.sig <<= 1; n.exp--; }
            }
        }
    } else {
        n.cls = SF_FINITE;
        n.sig = F | (1ull << (f->p - 1));
        n.exp = (int)E - f->bias;
    }
    return n;
}

static inline unsigned sf_bitlen(sf_u128 m) {
    unsigned n = 0;
    while (m) { m >>= 1; n++; }
    return n;
}

/* Round the exact value (m + d) * 2^lsb, 0 <= d < 1 and d > 0 iff `sticky`,
 * to format f under env, set OE/UE/PE as x86 does, and return the bits. */
static inline uint64_t sf_round_pack(const sf_fmt *f, const sf_env *env, unsigned sign, int lsb,
                                     sf_u128 m, int sticky, unsigned *flags) {
    const unsigned p = f->p;
    if (m == 0 && !sticky) return sf_zero(f, sign);
    if (!sticky) {
        while (sf_bitlen(m) < p + 2) { m <<= 1; lsb--; }   /* exact: no information below the LSB */
    }
    unsigned n = sf_bitlen(m);
    int E = lsb + (int)n - 1;                              /* exponent of the leading bit */
    int tiny_before = E < f->emin;
    unsigned shift = tiny_before ? (unsigned)((int)n - (int)p + (f->emin - E)) : n - p;

    sf_u128 q, rem, half;
    if (shift >= 128) { q = 0; rem = m; half = 0; }
    else { q = m >> shift; rem = m & (((sf_u128)1 << shift) - 1); half = (sf_u128)1 << (shift - 1); }
    int inexact = rem != 0 || sticky;
    int up = 0;
    switch (env->rc) {
    case SF_RN:
        if (shift >= 128) up = 0;                          /* value < half of the smallest step */
        else up = rem > half || (rem == half && (sticky || (q & 1)));
        break;
    case SF_RZ: up = 0; break;
    case SF_RU: up = inexact && !sign; break;
    default:    up = inexact && sign; break;               /* SF_RD */
    }
    q += up;
    int qlsb = lsb + (int)shift;
    if (sf_bitlen(q) > p) { q >>= 1; qlsb++; }            /* carry out: 100..0, exact */

    /* x86 detects tininess AFTER rounding (as if the exponent were unbounded):
     * the result is tiny iff its magnitude, rounded to p bits, is < 2^emin. */
    int tiny = tiny_before;
    if (tiny_before && E == f->emin - 1) {
        /* re-round at full precision p to see whether it reaches 2^emin */
        unsigned s2 = n - p;
        sf_u128 q2 = m >> s2, r2 = m & (((sf_u128)1 << s2) - 1), h2 = (sf_u128)1 << (s2 - 1);
        int inx2 = r2 != 0 || sticky, up2;
        switch (env->rc) {
        case SF_RN: up2 = r2 > h2 || (r2 == h2 && (sticky || (q2 & 1))); break;
        case SF_RZ: up2 = 0; break;
        case SF_RU: up2 = inx2 && !sign; break;
        default:    up2 = inx2 && sign; break;
        }
        if (sf_bitlen(q2 + (sf_u128)up2) > p) tiny = 0;
    }

    if (tiny && env->ftz) {                                /* x86: FTZ (underflow masked) */
        *flags |= SF_UE | SF_PE;
        return sf_zero(f, sign);
    }
    if (inexact) *flags |= SF_PE;
    if (tiny && inexact) *flags |= SF_UE;                  /* masked underflow: tiny AND inexact */

    if (q == 0) return sf_zero(f, sign);
    int Eres = qlsb + (int)sf_bitlen(q) - 1;
    if (Eres > f->emax) {
        *flags |= SF_OE | SF_PE;
        switch (env->rc) {
        case SF_RN: return sf_inf(f, sign);
        case SF_RZ: return sf_max(f, sign);
        case SF_RU: return sign ? sf_max(f, 1) : sf_inf(f, 0);
        default:    return sign ? sf_inf(f, 1) : sf_max(f, 0);
        }
    }
    uint64_t sbit = sign ? sf_signbit(f) : 0;
    if (Eres >= f->emin)
        return sbit | ((uint64_t)(Eres + f->bias) << (p - 1)) | ((uint64_t)q & sf_fracmask(f));
    return sbit | (uint64_t)q;                             /* subnormal: qlsb == emin - (p-1) */
}

/* NaN result for operations with NaN operand(s): x86 returns the first NaN
 * operand (quieted), else the second; any SNaN raises IE. */
static inline uint64_t sf_nan2(const sf_fmt *f, const sf_num *a, const sf_num *b, unsigned *flags) {
    if (a->cls == SF_SNAN || (b && b->cls == SF_SNAN)) *flags |= SF_IE;
    if (a->cls == SF_QNAN || a->cls == SF_SNAN) return a->bits | sf_quietbit(f);
    return b->bits | sf_quietbit(f);
}
static inline int sf_isnan(const sf_num *a) { return a->cls == SF_QNAN || a->cls == SF_SNAN; }

/* x86: DE (denormal operand) is raised for denormal sources unless DAZ is
 * set, and is not raised when a NaN operand makes the operation invalid
 * (that is decided by the hardware's pre-computation priority, verified). */
static inline void sf_denormal_flag(const sf_env *env, const sf_num *a, const sf_num *b, unsigned *flags) {
    if (env->daz) return;
    if (sf_isnan(a) || (b && sf_isnan(b))) return;
    if (a->denormal || (b && b->denormal)) *flags |= SF_DE;
}

/* ---- add / sub ---------------------------------------------------------- */
static inline uint64_t sf_add(const sf_fmt *f, const sf_env *env, uint64_t abits, uint64_t bbits,
                              int subtract, unsigned *flags) {
    sf_num a = sf_unpack(f, abits, env), b = sf_unpack(f, bbits, env);
    if (sf_isnan(&a) || sf_isnan(&b)) return sf_nan2(f, &a, &b, flags);
    unsigned bsign = b.sign ^ (unsigned)subtract;
    if (a.cls == SF_INF || b.cls == SF_INF) {
        if (a.cls == SF_INF && b.cls == SF_INF && a.sign != bsign) { *flags |= SF_IE; return sf_indefinite(f); }
        sf_denormal_flag(env, &a, &b, flags);
        return a.cls == SF_INF ? sf_inf(f, a.sign) : sf_inf(f, bsign);
    }
    sf_denormal_flag(env, &a, &b, flags);
    if (a.cls == SF_ZERO && b.cls == SF_ZERO) {
        unsigned s = a.sign == bsign ? a.sign : (env->rc == SF_RD);
        return sf_zero(f, s);
    }
    /* m * 2^lsb with 3 guard bits */
    const unsigned G = 3;
    sf_u128 ma = a.cls == SF_ZERO ? 0 : (sf_u128)a.sig << G;
    sf_u128 mb = b.cls == SF_ZERO ? 0 : (sf_u128)b.sig << G;
    int la = a.exp - (int)(f->p - 1) - (int)G, lb = b.exp - (int)(f->p - 1) - (int)G;
    if (a.cls == SF_ZERO) la = lb;
    if (b.cls == SF_ZERO) lb = la;
    /* order by magnitude: big first */
    unsigned sbig = a.sign, ssmall = bsign;
    if (lb > la || (lb == la && mb > ma)) {
        sf_u128 tm = ma; ma = mb; mb = tm;
        int tl = la; la = lb; lb = tl;
        sbig = bsign; ssmall = a.sign;
    }
    int sticky = 0;
    unsigned d = (unsigned)(la - lb);
    if (d) {
        if (d >= 128) { sticky = mb != 0; mb = 0; }
        else { sticky = (mb & (((sf_u128)1 << d) - 1)) != 0; mb >>= d; }
    }
    sf_u128 m;
    if (sbig == ssmall) {
        m = ma + mb;
    } else {
        m = ma - mb - (sticky ? 1 : 0);                   /* (ma - mb - 1) + (1 - eps) */
        if (m == 0 && !sticky) return sf_zero(f, env->rc == SF_RD);   /* exact cancellation */
    }
    return sf_round_pack(f, env, sbig, la, m, sticky, flags);
}

/* ---- mul ------------------------------------------------------------------ */
static inline uint64_t sf_mul(const sf_fmt *f, const sf_env *env, uint64_t abits, uint64_t bbits, unsigned *flags) {
    sf_num a = sf_unpack(f, abits, env), b = sf_unpack(f, bbits, env);
    if (sf_isnan(&a) || sf_isnan(&b)) return sf_nan2(f, &a, &b, flags);
    unsigned s = a.sign ^ b.sign;
    if (a.cls == SF_INF || b.cls == SF_INF) {
        if (a.cls == SF_ZERO || b.cls == SF_ZERO) { *flags |= SF_IE; return sf_indefinite(f); }
        sf_denormal_flag(env, &a, &b, flags);
        return sf_inf(f, s);
    }
    sf_denormal_flag(env, &a, &b, flags);
    if (a.cls == SF_ZERO || b.cls == SF_ZERO) return sf_zero(f, s);
    sf_u128 m = (sf_u128)a.sig * b.sig;
    int lsb = (a.exp - (int)(f->p - 1)) + (b.exp - (int)(f->p - 1));
    return sf_round_pack(f, env, s, lsb, m, 0, flags);
}

/* ---- div ------------------------------------------------------------------ */
static inline uint64_t sf_div(const sf_fmt *f, const sf_env *env, uint64_t abits, uint64_t bbits, unsigned *flags) {
    sf_num a = sf_unpack(f, abits, env), b = sf_unpack(f, bbits, env);
    if (sf_isnan(&a) || sf_isnan(&b)) return sf_nan2(f, &a, &b, flags);
    unsigned s = a.sign ^ b.sign;
    if (a.cls == SF_INF) {
        if (b.cls == SF_INF) { *flags |= SF_IE; return sf_indefinite(f); }
        sf_denormal_flag(env, &a, &b, flags);
        return sf_inf(f, s);
    }
    if (b.cls == SF_INF) { sf_denormal_flag(env, &a, &b, flags); return sf_zero(f, s); }
    if (b.cls == SF_ZERO) {
        if (a.cls == SF_ZERO) { *flags |= SF_IE; return sf_indefinite(f); }
        *flags |= SF_ZE;                                   /* x86: ZE without DE for a denormal dividend */
        return sf_inf(f, s);
    }
    sf_denormal_flag(env, &a, &b, flags);
    if (a.cls == SF_ZERO) return sf_zero(f, s);
    unsigned k = f->p + 2;
    sf_u128 num = (sf_u128)a.sig << k;
    sf_u128 q = num / b.sig, r = num % b.sig;
    int lsb = (a.exp - (int)(f->p - 1)) - (int)k - (b.exp - (int)(f->p - 1));
    return sf_round_pack(f, env, s, lsb, q, r != 0, flags);
}

/* ---- sqrt ----------------------------------------------------------------- */
static inline sf_u128 sf_isqrt(sf_u128 n, sf_u128 *rem) {
    sf_u128 res = 0, bit = (sf_u128)1 << 126;
    while (bit > n) bit >>= 2;
    while (bit) {
        if (n >= res + bit) { n -= res + bit; res = (res >> 1) + bit; }
        else res >>= 1;
        bit >>= 2;
    }
    *rem = n;
    return res;
}
static inline uint64_t sf_sqrt(const sf_fmt *f, const sf_env *env, uint64_t bits, unsigned *flags) {
    sf_num a = sf_unpack(f, bits, env);
    if (sf_isnan(&a)) return sf_nan2(f, &a, 0, flags);
    if (a.cls == SF_ZERO) { sf_denormal_flag(env, &a, 0, flags); return sf_zero(f, a.sign); }  /* sqrt(-0) = -0 */
    if (a.sign) { *flags |= SF_IE; return sf_indefinite(f); }
    sf_denormal_flag(env, &a, 0, flags);
    if (a.cls == SF_INF) return sf_inf(f, 0);
    int lsb = a.exp - (int)(f->p - 1);
    unsigned sh = f->p + 5;
    if ((lsb - (int)sh) & 1) sh++;
    sf_u128 rem, root = sf_isqrt((sf_u128)a.sig << sh, &rem);
    return sf_round_pack(f, env, 0, (lsb - (int)sh) / 2, root, rem != 0, flags);
}

/* ---- conversions -------------------------------------------------------- */
/* binary64 -> binary32 (CVTSD2SS) */
static inline uint32_t sf_f64_to_f32(const sf_env *env, uint64_t bits, unsigned *flags) {
    sf_num a = sf_unpack(&SF_F64, bits, env);
    if (sf_isnan(&a)) {
        if (a.cls == SF_SNAN) *flags |= SF_IE;
        return (uint32_t)((bits >> 32) & 0x80000000u) | 0x7FC00000u | (uint32_t)((bits >> 29) & 0x003FFFFFu);
    }
    sf_denormal_flag(env, &a, 0, flags);
    if (a.cls == SF_INF) return (uint32_t)sf_inf(&SF_F32, a.sign);
    if (a.cls == SF_ZERO) return (uint32_t)sf_zero(&SF_F32, a.sign);
    return (uint32_t)sf_round_pack(&SF_F32, env, a.sign, a.exp - 52, a.sig, 0, flags);
}
/* binary32 -> binary64 (CVTSS2SD): always exact for finite values */
static inline uint64_t sf_f32_to_f64(const sf_env *env, uint32_t bits, unsigned *flags) {
    sf_num a = sf_unpack(&SF_F32, bits, env);
    if (sf_isnan(&a)) {
        if (a.cls == SF_SNAN) *flags |= SF_IE;
        return ((uint64_t)(bits & 0x80000000u) << 32) | 0x7FF8000000000000ull | ((uint64_t)(bits & 0x003FFFFFu) << 29);
    }
    sf_denormal_flag(env, &a, 0, flags);
    if (a.cls == SF_INF) return sf_inf(&SF_F64, a.sign);
    if (a.cls == SF_ZERO) return sf_zero(&SF_F64, a.sign);
    sf_env exact = *env;
    exact.ftz = 0;                                         /* every binary32 value is a normal binary64 */
    return sf_round_pack(&SF_F64, &exact, a.sign, a.exp - 23, a.sig, 0, flags);
}
/* signed integer -> float (CVTSI2SD / CVTSI2SS) */
static inline uint64_t sf_from_int(const sf_fmt *f, const sf_env *env, int64_t v, unsigned *flags) {
    if (v == 0) return 0;
    unsigned s = v < 0;
    uint64_t mag = s ? 0 - (uint64_t)v : (uint64_t)v;
    sf_env e = *env;
    e.ftz = 0;                                             /* integers are never tiny */
    return sf_round_pack(f, &e, s, 0, mag, 0, flags);
}
/* float -> signed integer (CVTSD2SI / CVTTSD2SI ...). truncate: use RZ.
 * NaN / infinity / out of range -> IE and the integer indefinite 0x80..0. */
static inline uint64_t sf_to_int(const sf_fmt *f, const sf_env *env, uint64_t bits, unsigned width,
                                 int truncate, unsigned *flags) {
    uint64_t indef = width == 64 ? 0x8000000000000000ull : 0x80000000ull;
    sf_num a = sf_unpack(f, bits, env);
    if (a.cls == SF_QNAN || a.cls == SF_SNAN || a.cls == SF_INF) { *flags |= SF_IE; return indef; }
    if (a.cls == SF_ZERO) return 0;
    int lsb = a.exp - (int)(f->p - 1);
    sf_u128 q;
    int inexact = 0;
    if (lsb >= 0) {
        if (lsb > 64) { *flags |= SF_IE; return indef; }
        q = (sf_u128)a.sig << lsb;
    } else {
        unsigned sh = (unsigned)(-lsb);
        sf_u128 m = a.sig, rem, half;
        if (sh >= 128) { q = 0; rem = m; half = 0; }
        else { q = m >> sh; rem = m & (((sf_u128)1 << sh) - 1); half = (sf_u128)1 << (sh - 1); }
        inexact = rem != 0;
        unsigned rc = truncate ? SF_RZ : env->rc;
        int up;
        switch (rc) {
        case SF_RN: up = sh < 128 && (rem > half || (rem == half && (q & 1))); break;
        case SF_RZ: up = 0; break;
        case SF_RU: up = inexact && !a.sign; break;
        default:    up = inexact && a.sign; break;
        }
        q += up;
    }
    sf_u128 lim = (sf_u128)1 << (width - 1);
    if (a.sign ? q > lim : q >= lim) { *flags |= SF_IE; return indef; }
    if (inexact) *flags |= SF_PE;
    uint64_t r = a.sign ? (uint64_t)(0 - (uint64_t)q) : (uint64_t)q;
    return width == 64 ? r : (r & 0xffffffffu);
}

/* ---- comparisons ---------------------------------------------------------- */
/* returns -1, 0, 1 for ordered operands, 2 for unordered (after DAZ) */
static inline int sf_compare(const sf_fmt *f, const sf_num *a, const sf_num *b) {
    (void)f;
    if (sf_isnan(a) || sf_isnan(b)) return 2;
    if (a->cls == SF_ZERO && b->cls == SF_ZERO) return 0;
    /* map to a totally ordered key: sign-magnitude on (class, exp, sig) */
    #define SF_KEY(x) ((x)->cls == SF_ZERO ? (sf_u128)0 : (x)->cls == SF_INF ? ~(sf_u128)0 >> 1 \
                       : ((sf_u128)(uint64_t)((int64_t)(x)->exp + 0x10000) << 64) | (x)->sig)
    sf_u128 ka = SF_KEY(a), kb = SF_KEY(b);
    #undef SF_KEY
    if (a->cls == SF_ZERO) return b->sign ? 1 : -1;
    if (b->cls == SF_ZERO) return a->sign ? -1 : 1;
    if (a->sign != b->sign) return a->sign ? -1 : 1;
    if (ka == kb) return 0;
    int lt = ka < kb;
    return a->sign ? (lt ? 1 : -1) : (lt ? -1 : 1);
}
#endif
