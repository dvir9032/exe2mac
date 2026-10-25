/* Portable unit tests for runtime/x86_simd.h (runs on ARM64 too). Expected
 * values are written from the SDM definitions; the CVTSI2SS cases were
 * computed with exact integer rounding (round-to-nearest-even), including
 * ties that only a sticky bit can resolve. */
#include <inttypes.h>
#include <stdio.h>

#include "runtime/x86_simd.h"

/* guest state with the Windows default MXCSR (0x1F80: all exceptions masked) */
static x86_state G = { .mxcsr = 0x1F80u };

static int failures, checks;
#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); checks++; if (_a != _b) { failures++; \
    fprintf(stderr, "%s:%d: %s == 0x%016" PRIx64 ", expected 0x%016" PRIx64 "\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)
#define V(lo, hi) ((v128){ (lo), (hi) })

static const struct { uint64_t in; uint32_t out; } cvt[] = {
    {0x0040000040000000ull, 0x5a800000u},  /* 2^54 + 2^30: exact tie -> even */
    {0x0040000040000001ull, 0x5a800001u},  /* tie + 1: needs the sticky bit */
    {0x0800001800000000ull, 0x5d000002u},
    {0x4000004000000001ull, 0x5e800001u},
    {0xbfffffbfffffffffull, 0xde800001u},
    {0x7fffffffffffffffull, 0x5f000000u},
    {0x8000000000000000ull, 0xdf000000u},
    {0x0020000000000001ull, 0x5a000000u},
    {0x0000000001000001ull, 0x4b800000u},
    {0xfffffffffeffffffull, 0xcb800000u},
    {0x4000005fffffffffull, 0x5e800001u},
};

int main(void) {
    v128 a = V(0x8001fffe7f80ff00ull, 0x0102030405060708ull), b = V(0x0101010101010101ull, 0xffffffffffffffffull);
    EQ(v_add(a, b, 8).lo, 0x810200ff80810001ull);                 /* byte lanes wrap: fe+01=ff, ff+01=00 */
    EQ(v_add(a, b, 16).hi, 0x0101030305050707ull);
    EQ(v_sub(a, b, 32).lo, 0x7f00fefd7e7ffdffull);
    EQ(v_cmpgt(a, V(0, 0), 8).lo, 0x00ff0000ff000000ull);        /* only 0x7f and 0x01 are > 0 signed */
    EQ(v_cmpgt(V(0x7f80, 0), V(0, 0), 8).lo, 0xff00ull);         /* 0x7f > 0 signed; 0x80 < 0 */
    EQ(v_cmpeq(V(0x00ff00ff, 0), V(0x00ff0000, 0), 16).lo, 0xffffffffffff0000ull);
    EQ(v_minmax(V(0x80, 0), V(0x7f, 0), 8, 0, 0).lo, 0x7full);    /* unsigned min */
    EQ(v_minmax(V(0x8000, 0), V(0x7fff, 0), 16, 1, 0).lo, 0x8000ull);  /* signed min */
    EQ(v_pack(V(0x7fff0100ffff0050ull, 0x0000800000ff7fffull), V(0, 0), 16, 1).lo, 0x0000ffffffff0050ull);  /* unsigned sat */
    EQ(v_pack(V(0x7fff0100ffff0050ull, 0), V(0, 0), 16, 0).lo, 0x000000007f7fff50ull);  /* signed sat */
    EQ(v_unpack(V(0x0706050403020100ull, 0x0f0e0d0c0b0a0908ull), V(0x1716151413121110ull, 0x1f1e1d1c1b1a1918ull), 8, 0).lo,
       0x1303120211011000ull);
    EQ(v_unpack(V(0x0706050403020100ull, 0x0f0e0d0c0b0a0908ull), V(0x1716151413121110ull, 0x1f1e1d1c1b1a1918ull), 8, 1).hi,
       0x1f0f1e0e1d0d1c0cull);
    EQ(v_pshufd(V(0x1111111100000000ull, 0x3333333322222222ull), 0x1b).lo, 0x2222222233333333ull);
    EQ(v_pshuflw(V(0x0003000200010000ull, 0xabcdull), 0x1b).lo, 0x0000000100020003ull);
    EQ(v_pshuflw(V(0x0003000200010000ull, 0xabcdull), 0x1b).hi, 0xabcdull);
    EQ(v_shift(V(0x8000ull, 0), 15, 16, 2).lo, 0xffffull);         /* psraw fills sign */
    EQ(v_shift(V(0x8000ull, 0), 99, 16, 2).lo, 0xffffull);         /* count >= 16: sign fill */
    EQ(v_shift(V(0x8000ull, 0), 16, 16, 1).lo, 0);                /* logical: zero */
    EQ(v_shift(V(1, 1), 63, 64, 0).hi, 0x8000000000000000ull);
    EQ(v_byteshift(V(0x0706050403020100ull, 0x0f0e0d0c0b0a0908ull), 3, 1).lo, 0x0403020100000000ull);
    EQ(v_byteshift(V(0x0706050403020100ull, 0x0f0e0d0c0b0a0908ull), 3, 0).hi, 0x0000000f0e0d0c0bull);
    EQ(v_movmsk(V(0x80000000000000ffull, 0x7f00000000000080ull), 8), 0x0181u);
    EQ(v_movmsk(V(0x8000000000000000ull, 0x0000000080000000ull), 32), 0x6u);
    EQ(v_mullw(V(0x8000ffff0003ull, 0), V(0x00020002fffeull, 0)).lo, 0x0000fffefffaull);
    EQ(v_fp64(&G, V(0x3ff0000000000000ull, 0), V(0x4000000000000000ull, 0), SSE_ADD).lo, 0x4008000000000000ull);
    EQ(v_fp64(&G, V(0, 0), V(0, 0), SSE_DIV).hi, F64_INDEFINITE);         /* 0/0 lane -> negative QNaN */
    EQ(v_fp32(&G, V(0x3f80000000000000ull, 0), V(0x3f80000000000000ull, 0), SSE_ADD).lo, 0x4000000000000000ull);
    for (unsigned i = 0; i < sizeof cvt / sizeof cvt[0]; i++) EQ(sse_cvtsi2ss(&G, cvt[i].in, 64), cvt[i].out);
    EQ(sse_cvtsi2ss(&G, 0xFFFFFFFF00000005ull, 32), 0x40a00000u);         /* only the low 32 bits */
    printf("checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
