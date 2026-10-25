// Fixture 6: loops that clang auto-vectorises with packed SSE2 at -O2
// (default flags, no -fno-vectorize). Integer and floating-point lanes.
// No arithmetic in this file overflows a signed type (no undefined behaviour).
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
static void ph(unsigned long long v) { print(" "); print_hex(v, 16); }

#define N 203                                   /* not a multiple of the vector width: tails run too */
static unsigned char bytes[N];
static short s16[N];
static int i32[N], j32[N];
static unsigned u32[N];
static long long i64[N];
static double dv[N], ev[N];
static float fv[N];

static unsigned long long seed = 0x9e3779b97f4a7c15ull;
static unsigned long long rnd(void) { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed; }

__attribute__((noinline)) static unsigned long long sum_bytes(const unsigned char *p, int n) {
    unsigned long long s = 0; for (int i = 0; i < n; i++) s += p[i]; return s;
}
__attribute__((noinline)) static int count_eq(const unsigned char *p, int n, unsigned char c) {
    int k = 0; for (int i = 0; i < n; i++) k += p[i] == c; return k;
}
__attribute__((noinline)) static unsigned sum_i32(const int *a, int n) {
    unsigned s = 0; for (int i = 0; i < n; i++) s += (unsigned)a[i]; return s;   /* wraps: no signed overflow */
}
__attribute__((noinline)) static long long sum_mul(const int *a, const int *b, int n) {
    long long s = 0; for (int i = 0; i < n; i++) s += (long long)a[i] * b[i]; return s;
}
__attribute__((noinline)) static int max_i32(const int *a, int n) {
    int m = a[0]; for (int i = 1; i < n; i++) m = a[i] > m ? a[i] : m; return m;
}
__attribute__((noinline)) static unsigned min_u32(const unsigned *a, int n) {
    unsigned m = a[0]; for (int i = 1; i < n; i++) m = a[i] < m ? a[i] : m; return m;
}
__attribute__((noinline)) static void add_arrays(int *d, const int *a, const int *b, int n) {
    for (int i = 0; i < n; i++) d[i] = a[i] + b[i] * 3 - (a[i] >> 2);
}
__attribute__((noinline)) static void widen(long long *d, const short *s, int n) {
    for (int i = 0; i < n; i++) d[i] = (long long)s[i] * 8;   /* not `<< 3`: shifting a negative value is UB */
}
__attribute__((noinline)) static void to_upper(unsigned char *p, int n) {
    for (int i = 0; i < n; i++) p[i] = (p[i] >= 'a' && p[i] <= 'z') ? (unsigned char)(p[i] - 32) : p[i];
}
__attribute__((noinline)) static long long xor_shift(const unsigned *a, int n) {
    unsigned long long h = 0; for (int i = 0; i < n; i++) h ^= ((unsigned long long)a[i] << (i & 7)) ^ (a[i] >> 3); return (long long)h;
}
__attribute__((noinline)) static double dot(const double *a, const double *b, int n) {
    double s = 0; for (int i = 0; i < n; i++) s += a[i] * b[i]; return s;
}
__attribute__((noinline)) static void axpy(double *y, const double *x, double k, int n) {
    for (int i = 0; i < n; i++) y[i] = y[i] + k * x[i];
}
__attribute__((noinline)) static void scale_f(float *p, float k, int n) {
    for (int i = 0; i < n; i++) p[i] = p[i] * k + 1.0f;
}

void start(void) {
    out = GetStdHandle((DWORD)-11);
    for (int i = 0; i < N; i++) {
        unsigned long long r = rnd();
        bytes[i] = (unsigned char)r;
        s16[i] = (short)(r >> 8);
        i32[i] = (int)((r >> 16) & 0x3fffffff) - 0x20000000;   /* |x| <= 2^29: no overflow below */
        j32[i] = (int)(r >> 40) - 0x800000;
        u32[i] = (unsigned)(r >> 24);
        dv[i] = (double)(int)(r >> 32) / 1024.0;
        ev[i] = (double)(i - 100) * 0.5;
        fv[i] = (float)(i % 17) - 8.0f;
    }
    print("bytes:"); ph(sum_bytes(bytes, N)); ph((unsigned long long)count_eq(bytes, N, bytes[7])); print("\n");
    print("i32:"); ph((unsigned)sum_i32(i32, N)); ph((unsigned long long)sum_mul(i32, j32, N));
    ph((unsigned)max_i32(i32, N)); ph(min_u32(u32, N)); print("\n");
    add_arrays(j32, i32, j32, N);
    print("add:"); ph((unsigned)j32[0]); ph((unsigned)j32[N / 2]); ph((unsigned)j32[N - 1]); ph((unsigned)sum_i32(j32, N)); print("\n");
    widen(i64, s16, N);
    print("widen:"); ph((unsigned long long)i64[0]); ph((unsigned long long)i64[N - 1]); print("\n");
    for (int i = 0; i < N; i++) bytes[i] = (unsigned char)(' ' + (bytes[i] % 95));
    to_upper(bytes, N);
    print("upper: "); put((const char *)bytes, 40); print("\n");
    print("xor:"); ph((unsigned long long)xor_shift(u32, N)); print("\n");
    union { double d; unsigned long long u; } c;
    c.d = dot(dv, ev, N); print("dot:"); ph(c.u); print("\n");
    axpy(dv, ev, 0.25, N);
    c.d = dot(dv, dv, N); print("axpy:"); ph(c.u); print("\n");
    scale_f(fv, 1.5f, N);
    union { float f; unsigned u; } cf;
    float fs = 0; for (int i = 0; i < N; i++) fs += fv[i];
    cf.f = fs; print("float:"); ph(cf.u); print("\n");
    ExitProcess(42);
}
