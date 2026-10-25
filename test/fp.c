// Fixture 4: scalar SSE floating point (double and float).
// Every result is printed as its exact IEEE-754 bit pattern, so the golden
// output checks rounding, signed zeros, infinities and NaN encodings.
// All conversions to integers are in range (out-of-range is UB in C; it is
// tested with hand-written snippets instead).
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);

// Normally provided by the MSVC CRT whenever floating point is used.
int _fltused = 0;

static HANDLE out;
static void put(const char *s, int n) { DWORD w; WriteFile(out, s, (DWORD)n, &w, 0); }
static void print(const char *s) { int n = 0; while (s[n]) n++; put(s, n); }
static void print_hex(unsigned long long v, int digits) {
    static const char d[] = "0123456789abcdef";
    char buf[16];
    for (int i = digits - 1; i >= 0; i--) { buf[i] = d[v & 15]; v >>= 4; }
    put(buf, digits);
}
static void print_i(long long v) {
    char buf[24];
    int i = 24, neg = v < 0;
    unsigned long long u = neg ? 0 - (unsigned long long)v : (unsigned long long)v;
    do { buf[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (neg) buf[--i] = '-';
    put(buf + i, 24 - i);
}
static unsigned long long dbits(double x) { union { double d; unsigned long long u; } c; c.d = x; return c.u; }
static unsigned fbits(float x) { union { float f; unsigned u; } c; c.f = x; return c.u; }
static void pd(double x) { print(" "); print_hex(dbits(x), 16); }
static void pf(float x) { print(" "); print_hex(fbits(x), 8); }

#define N 8
static volatile double dv[N] = { 1.5, -2.25, 0.1, 1e308, 4.9406564584124654e-324, -0.0, 1.0 / 0.0, 3.0 };
static volatile float fv[4] = { 1.5f, -0.1f, 3.4e38f, 1e-45f };
static volatile long long iv[4] = { 0, -1, 9007199254740993LL, 9223372036854775807LL };

__attribute__((noinline)) static double dmax(double a, double b) { return a > b ? a : b; }
__attribute__((noinline)) static double dmin(double a, double b) { return a < b ? a : b; }
__attribute__((noinline)) static double dabs(double a) { return __builtin_fabs(a); }
__attribute__((noinline)) static double dneg(double a) { return -a; }

void start(void) {
    out = GetStdHandle((DWORD)-11);
    int score = 0;

    print("add:"); for (int i = 0; i + 1 < N; i++) pd(dv[i] + dv[i + 1]); print("\n");
    print("sub:"); for (int i = 0; i + 1 < N; i++) pd(dv[i] - dv[i + 1]); print("\n");
    print("mul:"); for (int i = 0; i + 1 < N; i++) pd(dv[i] * dv[i + 1]); print("\n");
    print("div:"); for (int i = 0; i + 1 < N; i++) pd(dv[i] / dv[i + 1]); print("\n");
    print("sqrt:"); for (int i = 0; i < N; i++) pd(__builtin_sqrt(dv[i])); print("\n");
    print("nan:");
    double z = dv[5], inf = dv[6];
    pd(z / z); pd(inf - inf); pd(__builtin_sqrt(dv[1])); pd((z / z) + 1.0); pd(1.0 + (inf - inf));
    print("\n");
    print("minmax:"); for (int i = 0; i + 1 < N; i++) { pd(dmin(dv[i], dv[i + 1])); pd(dmax(dv[i], dv[i + 1])); }
    pd(dmin(z / z, 1.0)); pd(dmax(1.0, z / z)); pd(dmin(0.0, -0.0)); pd(dmax(-0.0, 0.0));
    print("\n");
    print("absneg:"); for (int i = 0; i < N; i++) { pd(dabs(dv[i])); pd(dneg(dv[i])); } print("\n");
    print("cmp:");
    for (int i = 0; i + 1 < N; i++) {
        double a = dv[i], b = dv[i + 1];
        int c = (a < b) + 2 * (a == b) + 4 * (a > b) + 8 * (a != a);
        print(" "); print_i(c); score += c;
    }
    { double n = z / z; int c = (n < 1.0) + 2 * (n == n) + 4 * (n > 1.0) + 8 * (n != n); print(" "); print_i(c); score += c; }
    print("\n");
    print("d2i:");
    for (int i = 0; i < N; i++) {
        double x = dv[i];
        if (x > -1e18 && x < 1e18) { print(" "); print_i((long long)x); print("/"); print_i((int)(x * 1000.0)); }
    }
    print("\n");
    print("i2d:"); for (int i = 0; i < 4; i++) pd((double)iv[i]); pd((double)(int)iv[1]); print("\n");
    print("float:");
    for (int i = 0; i + 1 < 4; i++) { pf(fv[i] + fv[i + 1]); pf(fv[i] * fv[i + 1]); pf(fv[i] / fv[i + 1]); }
    print("\n");
    print("f2d:"); for (int i = 0; i < 4; i++) pd((double)fv[i]); for (int i = 0; i < 3; i++) pf((float)dv[i]); pf((float)dv[3]); pf((float)dv[4]); print("\n");

    ExitProcess((unsigned)score);
}
