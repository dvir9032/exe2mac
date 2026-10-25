/* exe2mac guest x86-64 CPU state and instruction-semantic helpers.
 *
 * Rules followed throughout this file:
 *   - every value is carried in uint64_t and masked to the operand width;
 *   - no signed arithmetic is performed on values that could overflow
 *     (signed division is done only after the overflow cases are excluded);
 *   - flags are computed eagerly and stored as 0/1 bytes;
 *   - flags documented by Intel as "undefined" for an instruction are left
 *     unchanged. That is one legal outcome; correct guest code cannot depend
 *     on undefined flags. Defined flags are always computed exactly.
 *
 * This header has no host-ABI knowledge. Guest calls, the guest stack and
 * Windows x64 conventions live in guest memory and in x86_state, never in
 * host registers or the host stack.
 */
#ifndef EXE2MAC_X86_CPU_H
#define EXE2MAC_X86_CPU_H

#include <stdint.h>
#include "guest_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    X86_RAX, X86_RCX, X86_RDX, X86_RBX, X86_RSP, X86_RBP, X86_RSI, X86_RDI,
    X86_R8, X86_R9, X86_R10, X86_R11, X86_R12, X86_R13, X86_R14, X86_R15
};

typedef struct x86_state {
    uint64_t gpr[16];
    uint64_t rip;            /* guest VA of the current / last return target */
    uint8_t cf, pf, af, zf, sf, of, df;
    struct { uint64_t lo, hi; } xmm[16];   /* SSE registers (only moves are implemented) */
    guest_mem *mem;
} x86_state;

/* Fault reporting (runtime/fault.c). Never returns. */
_Noreturn void exe2mac_fault(const x86_state *s, const char *what, uint64_t detail);

/* ------------------------------------------------------------------ */
/* width helpers                                                        */
/* ------------------------------------------------------------------ */
static inline uint64_t x86_mask(unsigned bits) {
    return bits >= 64 ? ~(uint64_t)0 : (((uint64_t)1 << bits) - 1);
}
static inline uint64_t x86_msb(uint64_t v, unsigned bits) {
    return (v >> (bits - 1)) & 1;
}
/* sign-extend the low `from` bits of v to 64 bits */
static inline uint64_t x86_sext(uint64_t v, unsigned from) {
    v &= x86_mask(from);
    if (from < 64 && x86_msb(v, from)) v |= ~x86_mask(from);
    return v;
}
static inline uint8_t x86_parity8(uint64_t v) {
    uint8_t b = (uint8_t)v;
    b ^= (uint8_t)(b >> 4);
    b ^= (uint8_t)(b >> 2);
    b ^= (uint8_t)(b >> 1);
    return (uint8_t)((~b) & 1);   /* PF=1 when the low byte has an even number of set bits */
}

/* ------------------------------------------------------------------ */
/* register access                                                      */
/* ------------------------------------------------------------------ */
static inline uint64_t x86_get(const x86_state *s, int idx, unsigned bits, int high8) {
    if (high8) return (s->gpr[idx] >> 8) & 0xff;
    return s->gpr[idx] & x86_mask(bits);
}
/* 64: full write; 32: zero-extends to 64; 16/8: merge into the existing value. */
static inline void x86_set(x86_state *s, int idx, unsigned bits, int high8, uint64_t v) {
    if (high8) {
        s->gpr[idx] = (s->gpr[idx] & ~(uint64_t)0xff00) | ((v & 0xff) << 8);
    } else if (bits == 64) {
        s->gpr[idx] = v;
    } else if (bits == 32) {
        s->gpr[idx] = v & 0xffffffffu;
    } else {
        s->gpr[idx] = (s->gpr[idx] & ~x86_mask(bits)) | (v & x86_mask(bits));
    }
}

/* ------------------------------------------------------------------ */
/* flag computation                                                     */
/* ------------------------------------------------------------------ */
static inline void x86_set_szp(x86_state *s, uint64_t r, unsigned bits) {
    r &= x86_mask(bits);
    s->zf = r == 0;
    s->sf = (uint8_t)x86_msb(r, bits);
    s->pf = x86_parity8(r);
}

static inline uint64_t x86_add(x86_state *s, uint64_t a, uint64_t b, unsigned bits) {
    uint64_t m = x86_mask(bits);
    a &= m; b &= m;
    uint64_t r = (a + b) & m;
    s->cf = r < a;
    s->of = (uint8_t)x86_msb(~(a ^ b) & (a ^ r), bits);
    s->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    x86_set_szp(s, r, bits);
    return r;
}

/* SUB and CMP (CMP discards the result). */
static inline uint64_t x86_sub(x86_state *s, uint64_t a, uint64_t b, unsigned bits) {
    uint64_t m = x86_mask(bits);
    a &= m; b &= m;
    uint64_t r = (a - b) & m;
    s->cf = a < b;
    s->of = (uint8_t)x86_msb((a ^ b) & (a ^ r), bits);
    s->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    x86_set_szp(s, r, bits);
    return r;
}

/* AND/OR/XOR/TEST: CF=OF=0, SF/ZF/PF from result, AF undefined (unchanged). */
static inline uint64_t x86_logic(x86_state *s, uint64_t r, unsigned bits) {
    r &= x86_mask(bits);
    s->cf = 0;
    s->of = 0;
    x86_set_szp(s, r, bits);
    return r;
}
static inline uint64_t x86_and(x86_state *s, uint64_t a, uint64_t b, unsigned bits) { return x86_logic(s, a & b, bits); }
static inline uint64_t x86_or (x86_state *s, uint64_t a, uint64_t b, unsigned bits) { return x86_logic(s, a | b, bits); }
static inline uint64_t x86_xor(x86_state *s, uint64_t a, uint64_t b, unsigned bits) { return x86_logic(s, a ^ b, bits); }

/* INC/DEC: like ADD/SUB 1 but CF is preserved. */
static inline uint64_t x86_inc(x86_state *s, uint64_t a, unsigned bits) {
    uint8_t cf = s->cf;
    uint64_t r = x86_add(s, a, 1, bits);
    s->cf = cf;
    return r;
}
static inline uint64_t x86_dec(x86_state *s, uint64_t a, unsigned bits) {
    uint8_t cf = s->cf;
    uint64_t r = x86_sub(s, a, 1, bits);
    s->cf = cf;
    return r;
}

/* NEG: 0 - a; CF = (a != 0). */
static inline uint64_t x86_neg(x86_state *s, uint64_t a, unsigned bits) {
    uint64_t r = x86_sub(s, 0, a, bits);
    s->cf = (a & x86_mask(bits)) != 0;
    return r;
}

/* SHR r/m, count. Count is masked to 6 bits (64-bit) or 5 bits (others).
 * Count 0: no flags change. CF = last bit shifted out. OF = MSB(original)
 * when count == 1, otherwise undefined (unchanged). AF undefined. */
static inline uint64_t x86_shr(x86_state *s, uint64_t a, uint64_t count, unsigned bits) {
    unsigned c = (unsigned)(count & (bits == 64 ? 0x3f : 0x1f));
    a &= x86_mask(bits);
    if (c == 0) return a;
    uint64_t r = c >= bits ? 0 : (a >> c);          /* 8/16-bit can have c >= bits */
    s->cf = c > bits ? 0 : (uint8_t)((a >> (c - 1)) & 1);
    if (c == 1) s->of = (uint8_t)x86_msb(a, bits);
    x86_set_szp(s, r, bits);
    return r;
}

/* ADC/SBB: like ADD/SUB with the incoming CF as an extra carry/borrow. */
static inline uint64_t x86_adc(x86_state *s, uint64_t a, uint64_t b, unsigned bits) {
    uint64_t m = x86_mask(bits), c = s->cf;
    a &= m; b &= m;
    uint64_t t = (a + b) & m;
    uint64_t r = (t + c) & m;
    s->cf = (uint8_t)((t < a) | (r < t));
    s->of = (uint8_t)x86_msb(~(a ^ b) & (a ^ r), bits);
    s->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    x86_set_szp(s, r, bits);
    return r;
}
static inline uint64_t x86_sbb(x86_state *s, uint64_t a, uint64_t b, unsigned bits) {
    uint64_t m = x86_mask(bits), c = s->cf;
    a &= m; b &= m;
    uint64_t t = (a - b) & m;
    uint64_t r = (t - c) & m;
    s->cf = (uint8_t)((a < b) | (t < c));
    s->of = (uint8_t)x86_msb((a ^ b) & (a ^ r), bits);
    s->af = (uint8_t)(((a ^ b ^ r) >> 4) & 1);
    x86_set_szp(s, r, bits);
    return r;
}

/* NOT: no flags. */
static inline uint64_t x86_not(uint64_t a, unsigned bits) { return ~a & x86_mask(bits); }

/* SHL/SAL r/m, count. Count masked like SHR; count 0 leaves flags.
 * CF = last bit shifted out (undefined when count > width: 8/16-bit only).
 * OF = MSB(result) XOR CF when count == 1, else undefined. AF undefined. */
static inline uint64_t x86_shl(x86_state *s, uint64_t a, uint64_t count, unsigned bits) {
    unsigned c = (unsigned)(count & (bits == 64 ? 0x3f : 0x1f));
    a &= x86_mask(bits);
    if (c == 0) return a;
    uint64_t r = c >= bits ? 0 : ((a << c) & x86_mask(bits));
    if (c <= bits) s->cf = (uint8_t)((a >> (bits - c)) & 1);
    if (c == 1) s->of = (uint8_t)(x86_msb(r, bits) ^ s->cf);
    x86_set_szp(s, r, bits);
    return r;
}

/* SAR r/m, count: arithmetic right shift. CF = last bit shifted out
 * (undefined when count > width), OF = 0 when count == 1. AF undefined.
 * Implemented on unsigned values: no implementation-defined signed shifts. */
static inline uint64_t x86_sar(x86_state *s, uint64_t a, uint64_t count, unsigned bits) {
    unsigned c = (unsigned)(count & (bits == 64 ? 0x3f : 0x1f));
    a &= x86_mask(bits);
    if (c == 0) return a;
    uint64_t sx = x86_sext(a, bits);                  /* 64-bit sign-extended view */
    uint64_t neg = sx >> 63;
    unsigned cc = c > 63 ? 63 : c;
    uint64_t r = neg ? ~((~sx) >> cc) : (sx >> cc);
    r &= x86_mask(bits);
    if (c <= bits) s->cf = (uint8_t)((sx >> (c - 1)) & 1);
    if (c == 1) s->of = 0;
    x86_set_szp(s, r, bits);
    return r;
}

/* DIV r/m (unsigned). 32: EDX:EAX / src; 64: RDX:RAX / src. #DE on zero
 * divisor or quotient overflow. All flags undefined (unchanged). */
static inline void x86_div(x86_state *s, uint64_t src, unsigned bits);

/* MUL r/m (unsigned): RDX:RAX = RAX * src (64) or EDX:EAX = EAX * src (32).
 * CF=OF = (high half != 0). SF/ZF/AF/PF undefined (unchanged). */
static inline void x86_mul(x86_state *s, uint64_t src, unsigned bits) {
    if (bits == 64) {
        unsigned __int128 p = (unsigned __int128)s->gpr[X86_RAX] * (unsigned __int128)src;
        uint64_t lo = (uint64_t)p, hi = (uint64_t)(p >> 64);
        s->gpr[X86_RAX] = lo;
        s->gpr[X86_RDX] = hi;
        s->cf = s->of = hi != 0;
    } else if (bits == 32) {
        uint64_t p = (s->gpr[X86_RAX] & 0xffffffffu) * (src & 0xffffffffu);
        x86_set(s, X86_RAX, 32, 0, p);
        x86_set(s, X86_RDX, 32, 0, p >> 32);
        s->cf = s->of = (p >> 32) != 0;
    } else {
        exe2mac_fault(s, "mul: unsupported operand width", bits);
    }
}

/* IMUL dst, src (two-operand, truncating). CF=OF = signed result did not fit.
 * SF/ZF/AF/PF undefined (unchanged). */
static inline uint64_t x86_imul2(x86_state *s, uint64_t a, uint64_t b, unsigned bits) {
    uint64_t m = x86_mask(bits);
    uint64_t r;
    int overflow;
    if (bits == 64) {
        __int128 sa = (__int128)(int64_t)a, sb = (__int128)(int64_t)b;
        /* |sa*sb| <= 2^126, always representable in __int128 */
        __int128 p = sa * sb;
        r = (uint64_t)p;
        overflow = p != (__int128)(int64_t)r;
    } else if (bits == 32 || bits == 16) {
        int64_t sa = (int64_t)x86_sext(a, bits), sb = (int64_t)x86_sext(b, bits);
        int64_t p = sa * sb;   /* |p| <= 2^62: no overflow */
        r = (uint64_t)p & m;
        overflow = (int64_t)x86_sext(r, bits) != p;
    } else {
        exe2mac_fault(s, "imul: unsupported operand width", bits);
    }
    s->cf = s->of = (uint8_t)overflow;
    return r;
}

/* IDIV r/m (signed). 32: EDX:EAX / src -> EAX quotient, EDX remainder.
 * 64: RDX:RAX / src. Divide-by-zero or quotient overflow raises #DE.
 * All flags undefined (unchanged). */
#define EXE2MAC_STATUS_INTEGER_DIVIDE_BY_ZERO 0xC0000094u
#define EXE2MAC_STATUS_INTEGER_OVERFLOW       0xC0000095u
_Noreturn void exe2mac_raise(const x86_state *s, uint32_t ntstatus, const char *what);

static inline void x86_idiv(x86_state *s, uint64_t src, unsigned bits) {
    if (bits == 32) {
        uint64_t raw = ((s->gpr[X86_RDX] & 0xffffffffu) << 32) | (s->gpr[X86_RAX] & 0xffffffffu);
        int64_t dividend = (int64_t)raw;
        int64_t divisor = (int64_t)x86_sext(src, 32);
        if (divisor == 0) exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_DIVIDE_BY_ZERO, "idiv32: divide by zero");
        if (divisor == -1 && dividend == INT64_MIN)
            exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_OVERFLOW, "idiv32: quotient overflow");
        int64_t q = dividend / divisor;   /* C truncates toward zero, as x86 does */
        int64_t r = dividend % divisor;
        if (q < INT32_MIN || q > INT32_MAX)
            exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_OVERFLOW, "idiv32: quotient overflow");
        x86_set(s, X86_RAX, 32, 0, (uint64_t)q);
        x86_set(s, X86_RDX, 32, 0, (uint64_t)r);
    } else if (bits == 64) {
        unsigned __int128 raw = ((unsigned __int128)s->gpr[X86_RDX] << 64) | s->gpr[X86_RAX];
        __int128 dividend = (__int128)raw;
        __int128 divisor = (__int128)(int64_t)src;
        if (divisor == 0) exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_DIVIDE_BY_ZERO, "idiv64: divide by zero");
        /* dividend == INT128_MIN with divisor == -1 is the only C-overflow case */
        unsigned __int128 int128_min = (unsigned __int128)1 << 127;
        if (divisor == -1 && raw == int128_min)
            exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_OVERFLOW, "idiv64: quotient overflow");
        __int128 q = dividend / divisor;
        __int128 r = dividend % divisor;
        if (q < (__int128)INT64_MIN || q > (__int128)INT64_MAX)
            exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_OVERFLOW, "idiv64: quotient overflow");
        s->gpr[X86_RAX] = (uint64_t)q;
        s->gpr[X86_RDX] = (uint64_t)r;
    } else {
        exe2mac_fault(s, "idiv: unsupported operand width", bits);
    }
}

static inline void x86_div(x86_state *s, uint64_t src, unsigned bits) {
    if (bits == 32) {
        uint64_t dividend = ((s->gpr[X86_RDX] & 0xffffffffu) << 32) | (s->gpr[X86_RAX] & 0xffffffffu);
        uint64_t divisor = src & 0xffffffffu;
        if (divisor == 0) exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_DIVIDE_BY_ZERO, "div32: divide by zero");
        uint64_t q = dividend / divisor, r = dividend % divisor;
        if (q > 0xffffffffu) exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_OVERFLOW, "div32: quotient overflow");
        x86_set(s, X86_RAX, 32, 0, q);
        x86_set(s, X86_RDX, 32, 0, r);
    } else if (bits == 64) {
        unsigned __int128 dividend = ((unsigned __int128)s->gpr[X86_RDX] << 64) | s->gpr[X86_RAX];
        if (src == 0) exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_DIVIDE_BY_ZERO, "div64: divide by zero");
        if (s->gpr[X86_RDX] >= src) exe2mac_raise(s, EXE2MAC_STATUS_INTEGER_OVERFLOW, "div64: quotient overflow");
        s->gpr[X86_RAX] = (uint64_t)(dividend / src);
        s->gpr[X86_RDX] = (uint64_t)(dividend % src);
    } else {
        exe2mac_fault(s, "div: unsupported operand width", bits);
    }
}

/* ------------------------------------------------------------------ */
/* string operations (byte granularity, 64-bit addressing)              */
/* ------------------------------------------------------------------ */
/* REP STOSB: while RCX != 0 { [RDI] = AL; RDI += DF ? -1 : 1; RCX-- }. No flags. */
static inline void x86_rep_stosb(x86_state *s) {
    uint64_t step = s->df ? ~(uint64_t)0 : 1;
    uint8_t al = (uint8_t)s->gpr[X86_RAX];
    while (s->gpr[X86_RCX] != 0) {
        guest_st8(s->mem, s->gpr[X86_RDI], al);
        s->gpr[X86_RDI] += step;
        s->gpr[X86_RCX] -= 1;
    }
}
/* REP MOVSB: byte-by-byte, so overlapping ranges behave exactly like hardware. */
static inline void x86_rep_movsb(x86_state *s) {
    uint64_t step = s->df ? ~(uint64_t)0 : 1;
    while (s->gpr[X86_RCX] != 0) {
        guest_st8(s->mem, s->gpr[X86_RDI], guest_ld8(s->mem, s->gpr[X86_RSI]));
        s->gpr[X86_RSI] += step;
        s->gpr[X86_RDI] += step;
        s->gpr[X86_RCX] -= 1;
    }
}

/* ------------------------------------------------------------------ */
/* SSE moves                                                            */
/* ------------------------------------------------------------------ */
#define EXE2MAC_STATUS_ACCESS_VIOLATION_CODE 0xC0000005u
/* MOVAPS m128 requires 16-byte alignment (#GP otherwise; Windows reports an access violation). */
static inline void x86_ld128(x86_state *s, int x, uint64_t va, int aligned) {
    if (aligned && (va & 15)) exe2mac_raise(s, EXE2MAC_STATUS_ACCESS_VIOLATION_CODE, "movaps: misaligned operand");
    (void)guest_ptr(s->mem, va, 16, GUEST_PERM_R);
    s->xmm[x].lo = guest_ld64(s->mem, va);
    s->xmm[x].hi = guest_ld64(s->mem, va + 8);
}
static inline void x86_st128(x86_state *s, int x, uint64_t va, int aligned) {
    if (aligned && (va & 15)) exe2mac_raise(s, EXE2MAC_STATUS_ACCESS_VIOLATION_CODE, "movaps: misaligned operand");
    (void)guest_ptr(s->mem, va, 16, GUEST_PERM_W);     /* fault before any partial write */
    guest_st64(s->mem, va, s->xmm[x].lo);
    guest_st64(s->mem, va + 8, s->xmm[x].hi);
}

/* CDQ: EDX = sign of EAX (32-bit write, zero-extends RDX). CQO: RDX = sign of RAX. */
static inline void x86_cdq(x86_state *s) {
    x86_set(s, X86_RDX, 32, 0, x86_msb(s->gpr[X86_RAX], 32) ? 0xffffffffu : 0);
}
static inline void x86_cqo(x86_state *s) {
    s->gpr[X86_RDX] = x86_msb(s->gpr[X86_RAX], 64) ? ~(uint64_t)0 : 0;
}

/* ------------------------------------------------------------------ */
/* condition codes (hardware encoding order, low nibble of Jcc opcode)  */
/* ------------------------------------------------------------------ */
enum {
    X86_CC_O, X86_CC_NO, X86_CC_B, X86_CC_AE, X86_CC_E, X86_CC_NE, X86_CC_BE, X86_CC_A,
    X86_CC_S, X86_CC_NS, X86_CC_P, X86_CC_NP, X86_CC_L, X86_CC_GE, X86_CC_LE, X86_CC_G
};

static inline int x86_cond(const x86_state *s, int cc) {
    int r;
    switch (cc >> 1) {
    case 0: r = s->of; break;
    case 1: r = s->cf; break;
    case 2: r = s->zf; break;
    case 3: r = s->cf | s->zf; break;
    case 4: r = s->sf; break;
    case 5: r = s->pf; break;
    case 6: r = s->sf != s->of; break;
    default: r = s->zf | (s->sf != s->of); break;
    }
    return (cc & 1) ? !r : r;
}

/* ------------------------------------------------------------------ */
/* guest stack (always through guest memory)                            */
/* ------------------------------------------------------------------ */
static inline void x86_push64(x86_state *s, uint64_t v) {
    uint64_t sp = s->gpr[X86_RSP] - 8;
    guest_st64(s->mem, sp, v);        /* faults before RSP is updated */
    s->gpr[X86_RSP] = sp;
}
static inline uint64_t x86_pop64(x86_state *s) {
    uint64_t v = guest_ld64(s->mem, s->gpr[X86_RSP]);
    s->gpr[X86_RSP] += 8;
    return v;
}

#ifdef __cplusplus
}
#endif
#endif
