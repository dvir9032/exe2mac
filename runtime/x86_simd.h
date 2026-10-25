/* exe2mac packed SSE/SSE2 semantics (128-bit XMM, lane loops).
 *
 * A vector is two little-endian 64-bit halves (lo = bytes 0..7, hi = 8..15),
 * the same layout as x86_state.xmm[]. Lanes are extracted and inserted
 * arithmetically, so the code does not depend on host endianness or on host
 * SIMD. Packed floating-point lanes reuse the scalar helpers of x86_sse.h,
 * so every lane follows the x86 NaN / indefinite rules.
 */
#ifndef EXE2MAC_X86_SIMD_H
#define EXE2MAC_X86_SIMD_H

#include <stdint.h>
#include "x86_sse.h"

typedef struct v128 { uint64_t lo, hi; } v128;

static inline v128 v_xmm(const x86_state *s, int x) { v128 v = { s->xmm[x].lo, s->xmm[x].hi }; return v; }
static inline void v_set_xmm(x86_state *s, int x, v128 v) { s->xmm[x].lo = v.lo; s->xmm[x].hi = v.hi; }

/* lane access: bits in {8,16,32,64}, i in [0, 128/bits) */
static inline uint64_t v_get(v128 v, unsigned bits, unsigned i) {
    unsigned bit = i * bits;
    uint64_t half = bit < 64 ? v.lo : v.hi;
    unsigned sh = bit & 63;
    return bits == 64 ? half : (half >> sh) & ((1ull << bits) - 1);
}
static inline v128 v_put(v128 v, unsigned bits, unsigned i, uint64_t x) {
    unsigned bit = i * bits;
    unsigned sh = bit & 63;
    uint64_t m = bits == 64 ? ~0ull : (((1ull << bits) - 1) << sh);
    uint64_t val = bits == 64 ? x : ((x << sh) & m);
    if (bit < 64) v.lo = (v.lo & ~m) | val; else v.hi = (v.hi & ~m) | val;
    return v;
}
static inline int64_t v_sext(uint64_t x, unsigned bits) { return (int64_t)x86_sext(x, bits); }

/* ---- integer arithmetic -------------------------------------------------- */
static inline v128 v_add(v128 a, v128 b, unsigned bits) {
    for (unsigned i = 0; i < 128 / bits; i++) a = v_put(a, bits, i, v_get(a, bits, i) + v_get(b, bits, i));
    return a;
}
static inline v128 v_sub(v128 a, v128 b, unsigned bits) {
    for (unsigned i = 0; i < 128 / bits; i++) a = v_put(a, bits, i, v_get(a, bits, i) - v_get(b, bits, i));
    return a;
}
/* PMULLW: low 16 bits of each 16x16 product (sign irrelevant for the low half) */
static inline v128 v_mullw(v128 a, v128 b) {
    for (unsigned i = 0; i < 8; i++) a = v_put(a, 16, i, v_get(a, 16, i) * v_get(b, 16, i));
    return a;
}
/* PMULUDQ: unsigned 32x32->64 of the even dword lanes */
static inline v128 v_muludq(v128 a, v128 b) {
    v128 r = { (a.lo & 0xffffffffu) * (b.lo & 0xffffffffu), (a.hi & 0xffffffffu) * (b.hi & 0xffffffffu) };
    return r;
}

/* ---- comparisons and min/max ------------------------------------------- */
static inline v128 v_cmpeq(v128 a, v128 b, unsigned bits) {
    for (unsigned i = 0; i < 128 / bits; i++)
        a = v_put(a, bits, i, v_get(a, bits, i) == v_get(b, bits, i) ? ~0ull : 0);
    return a;
}
static inline v128 v_cmpgt(v128 a, v128 b, unsigned bits) {      /* signed */
    for (unsigned i = 0; i < 128 / bits; i++)
        a = v_put(a, bits, i, v_sext(v_get(a, bits, i), bits) > v_sext(v_get(b, bits, i), bits) ? ~0ull : 0);
    return a;
}
static inline v128 v_minmax(v128 a, v128 b, unsigned bits, int is_signed, int want_max) {
    for (unsigned i = 0; i < 128 / bits; i++) {
        uint64_t x = v_get(a, bits, i), y = v_get(b, bits, i);
        int lt = is_signed ? v_sext(x, bits) < v_sext(y, bits) : x < y;
        a = v_put(a, bits, i, (want_max ? !lt : lt) ? x : y);
    }
    return a;
}

/* ---- pack with saturation ---------------------------------------------- */
static inline uint64_t sat_s(int64_t v, unsigned bits) {
    int64_t lo = -((int64_t)1 << (bits - 1)), hi = ((int64_t)1 << (bits - 1)) - 1;
    return (uint64_t)(v < lo ? lo : v > hi ? hi : v);
}
static inline uint64_t sat_u(int64_t v, unsigned bits) {
    int64_t hi = ((int64_t)1 << bits) - 1;
    return (uint64_t)(v < 0 ? 0 : v > hi ? hi : v);
}
/* PACKSSWB/PACKUSWB (words->bytes), PACKSSDW (dwords->words): dst lanes first, then src. */
static inline v128 v_pack(v128 a, v128 b, unsigned from_bits, int unsigned_sat) {
    v128 r = { 0, 0 };
    unsigned to = from_bits / 2, n = 128 / from_bits;
    for (unsigned i = 0; i < n; i++) {
        int64_t x = v_sext(v_get(a, from_bits, i), from_bits), y = v_sext(v_get(b, from_bits, i), from_bits);
        r = v_put(r, to, i, unsigned_sat ? sat_u(x, to) : sat_s(x, to));
        r = v_put(r, to, i + n, unsigned_sat ? sat_u(y, to) : sat_s(y, to));
    }
    return r;
}

/* ---- interleave ---------------------------------------------------------- */
/* PUNPCKL*: interleave the low halves of dst and src; PUNPCKH*: the high halves. */
static inline v128 v_unpack(v128 a, v128 b, unsigned bits, int high) {
    v128 r = { 0, 0 };
    unsigned n = 64 / bits, base = high ? n : 0;
    for (unsigned i = 0; i < n; i++) {
        r = v_put(r, bits, 2 * i, v_get(a, bits, base + i));
        r = v_put(r, bits, 2 * i + 1, v_get(b, bits, base + i));
    }
    return r;
}

/* ---- shuffles ------------------------------------------------------------ */
static inline v128 v_pshufd(v128 b, unsigned imm) {
    v128 r = { 0, 0 };
    for (unsigned i = 0; i < 4; i++) r = v_put(r, 32, i, v_get(b, 32, (imm >> (2 * i)) & 3));
    return r;
}
static inline v128 v_pshuflw(v128 b, unsigned imm) {      /* high qword copied */
    v128 r = { 0, b.hi };
    for (unsigned i = 0; i < 4; i++) r = v_put(r, 16, i, v_get(b, 16, (imm >> (2 * i)) & 3));
    return r;
}
static inline v128 v_pshufhw(v128 b, unsigned imm) {      /* low qword copied */
    v128 r = { b.lo, 0 };
    for (unsigned i = 0; i < 4; i++) r = v_put(r, 16, 4 + i, v_get(b, 16, 4 + ((imm >> (2 * i)) & 3)));
    return r;
}
/* SHUFPS: two lanes from dst, two from src */
static inline v128 v_shufps(v128 a, v128 b, unsigned imm) {
    v128 r = { 0, 0 };
    r = v_put(r, 32, 0, v_get(a, 32, imm & 3));
    r = v_put(r, 32, 1, v_get(a, 32, (imm >> 2) & 3));
    r = v_put(r, 32, 2, v_get(b, 32, (imm >> 4) & 3));
    r = v_put(r, 32, 3, v_get(b, 32, (imm >> 6) & 3));
    return r;
}

/* ---- shifts -------------------------------------------------------------- */
/* Count >= lane width: logical shifts give 0, arithmetic shifts give the sign
 * fill. Count comes from an imm8 or the low 64 bits of an XMM/m128 operand. */
static inline v128 v_shift(v128 a, uint64_t count, unsigned bits, int kind) {   /* 0=sll 1=srl 2=sra */
    for (unsigned i = 0; i < 128 / bits; i++) {
        uint64_t x = v_get(a, bits, i), r;
        if (kind == 2) {
            uint64_t c = count > bits - 1 ? bits - 1 : count;
            int64_t sx = v_sext(x, bits);
            r = sx < 0 ? ~((~(uint64_t)sx) >> c) : ((uint64_t)sx >> c);
        } else if (count >= bits) {
            r = 0;
        } else {
            r = kind == 0 ? x << count : x >> count;
        }
        a = v_put(a, bits, i, r);
    }
    return a;
}
/* PSLLDQ/PSRLDQ: whole-register byte shifts, count > 15 clears */
static inline v128 v_byteshift(v128 a, unsigned count, int left) {
    v128 r = { 0, 0 };
    if (count > 15) return r;
    for (unsigned i = 0; i < 16; i++) {
        int j = left ? (int)i - (int)count : (int)i + (int)count;
        if (j >= 0 && j < 16) r = v_put(r, 8, i, v_get(a, 8, (unsigned)j));
    }
    return r;
}

/* ---- masks --------------------------------------------------------------- */
static inline uint32_t v_movmsk(v128 a, unsigned bits) {     /* sign bit of each lane */
    uint32_t m = 0;
    for (unsigned i = 0; i < 128 / bits; i++) m |= (uint32_t)((v_get(a, bits, i) >> (bits - 1)) & 1) << i;
    return m;
}

/* ---- packed floating point (lane-wise scalar rules) ------------------------ */
/* Lanes are computed with flags accumulated, then recorded once (so an
 * unmasked exception in any lane faults before the destination is written). */
static inline v128 v_fp32(x86_state *s, v128 a, v128 b, int op) {
    sf_env e = sse_env(s); unsigned fl = 0;
    v128 r = a;
    for (unsigned i = 0; i < 4; i++)
        r = v_put(r, 32, i, sf_arith(&SF_F32, &e, v_get(a, 32, i), v_get(b, 32, i), op, &fl));
    sse_flags(s, fl);
    return r;
}
static inline v128 v_fp64(x86_state *s, v128 a, v128 b, int op) {
    sf_env e = sse_env(s); unsigned fl = 0;
    v128 r = { sf_arith(&SF_F64, &e, a.lo, b.lo, op, &fl), sf_arith(&SF_F64, &e, a.hi, b.hi, op, &fl) };
    sse_flags(s, fl);
    return r;
}

/* ---- packed conversions (flags of all lanes accumulate, recorded once) ---- */
/* CVTDQ2PS: 4 x int32 -> float, rounded per MXCSR.RC (PE) */
static inline v128 v_cvtdq2ps(x86_state *s, v128 a) {
    sf_env e = sse_env(s); unsigned fl = 0; v128 r = { 0, 0 };
    for (unsigned i = 0; i < 4; i++)
        r = v_put(r, 32, i, sf_from_int(&SF_F32, &e, v_sext(v_get(a, 32, i), 32), &fl));
    sse_flags(s, fl);
    return r;
}
/* CVTDQ2PD: low 2 x int32 -> double (always exact) */
static inline v128 v_cvtdq2pd(x86_state *s, uint64_t lo) {
    sf_env e = sse_env(s); unsigned fl = 0;
    v128 r = { sf_from_int(&SF_F64, &e, v_sext(lo & 0xffffffffu, 32), &fl),
               sf_from_int(&SF_F64, &e, v_sext(lo >> 32, 32), &fl) };
    sse_flags(s, fl);
    return r;
}
/* CVTPS2PD: low 2 x float -> double (IE for SNaN, DE for denormals unless DAZ) */
static inline v128 v_cvtps2pd(x86_state *s, uint64_t lo) {
    sf_env e = sse_env(s); unsigned fl = 0;
    v128 r = { sf_f32_to_f64(&e, (uint32_t)lo, &fl), sf_f32_to_f64(&e, (uint32_t)(lo >> 32), &fl) };
    sse_flags(s, fl);
    return r;
}
/* CVTPD2PS: 2 x double -> 2 x float in the low qword; the high qword is zeroed */
static inline v128 v_cvtpd2ps(x86_state *s, v128 a) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint64_t x = sf_f64_to_f32(&e, a.lo, &fl), y = sf_f64_to_f32(&e, a.hi, &fl);
    sse_flags(s, fl);
    v128 r = { x | (y << 32), 0 };
    return r;
}
/* CVT(T)PS2DQ: 4 x float -> int32 (indefinite 0x80000000 + IE when out of range / NaN) */
static inline v128 v_cvtps2dq(x86_state *s, v128 a, int truncate) {
    sf_env e = sse_env(s); unsigned fl = 0; v128 r = { 0, 0 };
    for (unsigned i = 0; i < 4; i++)
        r = v_put(r, 32, i, sf_to_int(&SF_F32, &e, v_get(a, 32, i), 32, truncate, &fl));
    sse_flags(s, fl);
    return r;
}
/* CVT(T)PD2DQ: 2 x double -> 2 x int32 in the low qword; the high qword is zeroed */
static inline v128 v_cvtpd2dq(x86_state *s, v128 a, int truncate) {
    sf_env e = sse_env(s); unsigned fl = 0;
    uint64_t x = sf_to_int(&SF_F64, &e, a.lo, 32, truncate, &fl), y = sf_to_int(&SF_F64, &e, a.hi, 32, truncate, &fl);
    sse_flags(s, fl);
    v128 r = { (x & 0xffffffffu) | (y << 32), 0 };
    return r;
}

#endif
