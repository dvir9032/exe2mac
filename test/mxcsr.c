// Fixture 8: MXCSR. Rounding control, FTZ, DAZ, sticky exception flags and
// an unmasked SIMD floating-point exception (which ends the process).
// Every operation runs inside inline asm between LDMXCSR and STMXCSR, so the
// compiler cannot fold or move it across the control-register changes.
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);

int _fltused = 0;
static HANDLE out;
static void put(const char *s, unsigned long long n) { DWORD w; WriteFile(out, s, (DWORD)n, &w, 0); }
static void print(const char *s) { unsigned long long n = 0; while (s[n]) n++; put(s, n); }
static void print_hex(unsigned long long v, int digits) {
    static const char d[] = "0123456789abcdef";
    char buf[16];
    for (int i = digits - 1; i >= 0; i--) { buf[i] = d[v & 15]; v >>= 4; }
    put(buf, (unsigned long long)digits);
}

#define DEF 0x1F80u
enum { ADD, MUL, DIV, SQRT, CVT };

__attribute__((noinline)) static unsigned long long run(int op, unsigned long long a, unsigned long long b,
                                                         unsigned csr, unsigned *flags) {
    unsigned long long r;
    unsigned after = 0, def = DEF;
    switch (op) {
    case ADD:
        __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; addsd %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %4; ldmxcsr %5"
                         : "=r"(r) : "r"(a), "r"(b), "m"(csr), "m"(after), "m"(def) : "xmm0", "xmm1", "memory");
        break;
    case MUL:
        __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; mulsd %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %4; ldmxcsr %5"
                         : "=r"(r) : "r"(a), "r"(b), "m"(csr), "m"(after), "m"(def) : "xmm0", "xmm1", "memory");
        break;
    case DIV:
        __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; divsd %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %4; ldmxcsr %5"
                         : "=r"(r) : "r"(a), "r"(b), "m"(csr), "m"(after), "m"(def) : "xmm0", "xmm1", "memory");
        break;
    case SQRT:
        __asm__ volatile("ldmxcsr %2; movq %1, %%xmm1; sqrtsd %%xmm1, %%xmm0; movq %%xmm0, %0; stmxcsr %3; ldmxcsr %4"
                         : "=r"(r) : "r"(a), "m"(csr), "m"(after), "m"(def) : "xmm0", "xmm1", "memory");
        (void)b;
        break;
    default:
        __asm__ volatile("ldmxcsr %2; movq %1, %%xmm0; cvtsd2si %%xmm0, %0; stmxcsr %3; ldmxcsr %4"
                         : "=r"(r) : "r"(a), "m"(csr), "m"(after), "m"(def) : "xmm0", "memory");
        (void)b;
        break;
    }
    *flags = after & 0x3f;
    return r;
}

static void show(const char *label, int op, unsigned long long a, unsigned long long b, unsigned csr) {
    unsigned fl;
    unsigned long long r = run(op, a, b, csr, &fl);
    print(label); print(" "); print_hex(r, 16); print(" "); print_hex(fl, 2); print("\n");
}

#define ONE   0x3FF0000000000000ull
#define THREE 0x4008000000000000ull
#define TEN   0x4024000000000000ull
#define RC(m) (DEF | ((unsigned)(m) << 13))

void start(void) {
    out = GetStdHandle((DWORD)-11);
    static const char *mode[4] = { "rn", "rd", "ru", "rz" };
    for (int m = 0; m < 4; m++) {
        print(mode[m]); print(":\n");
        show("  1/3  ", DIV, ONE, THREE, RC(m));
        show("  1/10 ", DIV, ONE, TEN, RC(m));
        show(" -1/10 ", DIV, ONE | 0x8000000000000000ull, TEN, RC(m));
        show("  1-1  ", ADD, ONE, ONE | 0x8000000000000000ull, RC(m));        /* exact zero: -0 only in rd */
        show("  max*2", MUL, 0x7FEFFFFFFFFFFFFFull, 0x4000000000000000ull, RC(m));
        show("  cvt 2.5 ", CVT, 0x4004000000000000ull, 0, RC(m));
        show("  cvt-2.5 ", CVT, 0xC004000000000000ull, 0, RC(m));
        show("  cvt 3.5 ", CVT, 0x400C000000000000ull, 0, RC(m));
    }
    print("tiny:\n");
    show("  rn      ", MUL, 0x0010000000000000ull, 0x3FEFFFFFFFFFFFFFull, DEF);
    show("  rn ftz  ", MUL, 0x0010000000000000ull, 0x3FEFFFFFFFFFFFFFull, DEF | 0x8000u);
    show("  rz      ", MUL, 0x0010000000000000ull, 0x3FEFFFFFFFFFFFFFull, RC(3));
    show("  half    ", MUL, 0x0010000000000000ull, 0x3FE0000000000000ull, DEF);           /* exact subnormal */
    show("  half ftz", MUL, 0x0010000000000000ull, 0x3FE0000000000000ull, DEF | 0x8000u);
    print("daz:\n");
    show("  den+0   ", ADD, 0x0000000000000001ull, 0, DEF);
    show("  den+0 d ", ADD, 0x0000000000000001ull, 0, DEF | 0x40u);
    show("  den*1   ", MUL, 0x000FFFFFFFFFFFFFull, ONE, DEF);
    show("  den*1 d ", MUL, 0x000FFFFFFFFFFFFFull, ONE, DEF | 0x40u);
    print("invalid:\n");
    show("  0/0     ", DIV, 0, 0, DEF);
    show("  sqrt-1  ", SQRT, 0xBFF0000000000000ull, 0, DEF);
    show("  snan+1  ", ADD, 0x7FF0000000000001ull, ONE, DEF);
    show("  1/0     ", DIV, ONE, 0, DEF);
    print("unmasking ZE and dividing by zero\n");
    unsigned fl;
    run(DIV, ONE, 0, DEF & ~0x200u, &fl);        /* #XM: the process ends here */
    print("not reached\n");
    ExitProcess(0);
}
