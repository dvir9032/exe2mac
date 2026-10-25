/* Portable MXCSR test: replays results recorded from real x86-64 SSE hardware
 * (tests/c/mxcsr_vectors.h: 640 cases over all RC x FTZ x DAZ settings) and
 * checks bits and exception flags. Runs on ARM64 hosts, where host floating
 * point would differ (underflow rule, NaN encoding, rounding of conversions). */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "runtime/x86_sse.h"
#include "mxcsr_vectors.h"

int main(void) {
    int failures = 0, checks = 0;
    for (unsigned i = 0; i < sizeof MX_VECTORS / sizeof MX_VECTORS[0]; i++) {
        const struct mx_vec *v = &MX_VECTORS[i];
        x86_state s; memset(&s, 0, sizeof s);
        s.mxcsr = v->mxcsr;
        uint64_t r;
        switch (v->op) {
        case 0: r = sse_f64_arith(&s, v->a, v->b, SSE_ADD); break;
        case 1: r = sse_f64_arith(&s, v->a, v->b, SSE_SUB); break;
        case 2: r = sse_f64_arith(&s, v->a, v->b, SSE_MUL); break;
        case 3: r = sse_f64_arith(&s, v->a, v->b, SSE_DIV); break;
        case 4: r = sse_f64_sqrt(&s, v->a); break;
        case 5: r = sse_cvtsd2si(&s, v->a, 64); break;
        case 6: r = sse_cvttsd2si(&s, v->a, 64); break;
        default: r = sse_cvtsd2ss(&s, v->a); break;
        }
        checks++;
        if (r != v->r || (s.mxcsr & 0x3f) != v->flags) {
            failures++;
            fprintf(stderr, "case %u op %u mxcsr %04x: got %016" PRIx64 "/%02x expected %016" PRIx64 "/%02x\n",
                    i, v->op, v->mxcsr, r, s.mxcsr & 0x3f, v->r, v->flags);
        }
    }
    /* LDMXCSR keeps exactly what was loaded; reserved bits are a #GP (tested separately) */
    x86_state s; memset(&s, 0, sizeof s);
    sse_ldmxcsr(&s, 0xFFFFu);
    checks++; if (s.mxcsr != 0xFFFFu) failures++;
    printf("checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
