// Fixture 2: wider instruction coverage, still without a C runtime.
// Exercises byte/word loads (movzx/movsx), shifts by variable counts
// (shl/sar/shr), unsigned and signed division, boolean results (setcc),
// 128-bit arithmetic (adc/sbb), bitwise not, a switch statement, and a few
// instructions forced via inline assembly (xchg, rep stosb, rep movsb).
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);

static HANDLE out;

static void put(const char *s, int n) { DWORD w; WriteFile(out, s, (DWORD)n, &w, 0); }
static void print(const char *s) { int n = 0; while (s[n]) n++; put(s, n); }

static void print_u(unsigned long long u) {
    char buf[24];
    int i = 24;
    do { buf[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    put(buf + i, 24 - i);
}
static void print_i(long long v) {
    if (v < 0) { print("-"); print_u(0 - (unsigned long long)v); } else print_u((unsigned long long)v);
}
static void print_hex(unsigned long long v) {
    static const char digits[] = "0123456789abcdef";
    char buf[16];
    for (int i = 15; i >= 0; i--) { buf[i] = digits[v & 15]; v >>= 4; }
    print("0x"); put(buf, 16);
}
static void label(const char *s) { print(s); print(": "); }
static void nl(void) { print("\n"); }

// Opaque values so the compiler cannot fold the arithmetic away.
static volatile signed char vs8[4] = { -128, -1, 0, 127 };
static volatile unsigned char vu8[4] = { 0, 1, 200, 255 };
static volatile short vs16[3] = { -32768, -2, 30000 };
static volatile unsigned short vu16[3] = { 0, 40000, 65535 };
static volatile int counts[5] = { 0, 1, 7, 31, 33 };
static volatile long long sdiv[4][2] = { {100, 7}, {-100, 7}, {100, -7}, {-9223372036854775807LL, 3} };
static volatile unsigned long long udiv[3][2] = { {1000000007ULL, 10}, {0xffffffffffffffffULL, 3}, {12345, 12346} };

__attribute__((noinline)) static int classify(int x) {
    switch (x) {
    case 0: return 11;
    case 1: return 22;
    case 2: return 33;
    case 3: return 44;
    case 4: return 55;
    case 5: return 66;
    default: return -1;
    }
}

__attribute__((noinline)) static unsigned long long swap_xchg(unsigned long long a, unsigned long long *p) {
    __asm__ volatile("xchg %0, %1" : "+r"(a), "+m"(*p));
    return a;
}

__attribute__((noinline)) static void fill(unsigned char *dst, unsigned char v, unsigned long long n) {
    __asm__ volatile("rep stosb" : "+D"(dst), "+c"(n) : "a"(v) : "memory");
}

__attribute__((noinline)) static void copy(unsigned char *dst, const unsigned char *src, unsigned long long n) {
    __asm__ volatile("rep movsb" : "+D"(dst), "+S"(src), "+c"(n) : : "memory");
}

void start(void) {
    out = GetStdHandle((DWORD)-11);
    unsigned long long check = 0;

    label("s8");
    for (int i = 0; i < 4; i++) { print(" "); print_i(vs8[i]); check += (unsigned long long)(long long)vs8[i]; }
    nl();
    label("u8");
    for (int i = 0; i < 4; i++) { print(" "); print_u(vu8[i]); check += vu8[i]; }
    nl();
    label("s16");
    for (int i = 0; i < 3; i++) { print(" "); print_i(vs16[i]); check += (unsigned long long)(long long)vs16[i]; }
    nl();
    label("u16");
    for (int i = 0; i < 3; i++) { print(" "); print_u(vu16[i]); check += vu16[i]; }
    nl();

    label("shl");
    for (int i = 0; i < 5; i++) { unsigned c = (unsigned)counts[i]; print(" "); print_hex(0x8000000000000001ULL << (c & 63)); }
    nl();
    label("sar");
    for (int i = 0; i < 5; i++) { unsigned c = (unsigned)counts[i]; print(" "); print_i((-1000000000000LL) >> (c & 63)); }
    nl();
    label("shr32");
    for (int i = 0; i < 5; i++) { unsigned c = (unsigned)counts[i]; print(" "); print_u(0xdeadbeefu >> (c & 31)); }
    nl();

    label("sdiv");
    for (int i = 0; i < 4; i++) {
        long long a = sdiv[i][0], b = sdiv[i][1];
        print(" "); print_i(a / b); print("r"); print_i(a % b);
    }
    nl();
    label("udiv");
    for (int i = 0; i < 3; i++) {
        unsigned long long a = udiv[i][0], b = udiv[i][1];
        print(" "); print_u(a / b); print("r"); print_u(a % b);
        check ^= a / b;
    }
    nl();

    label("cmp");
    for (int i = 0; i < 4; i++) {
        int a = vs8[i], b = vu8[i];
        print(" ");
        print_u((unsigned)(a < b) + 2u * (unsigned)(a == b) + 4u * (unsigned)((unsigned)a > (unsigned)b));
    }
    nl();

    unsigned __int128 x = ((unsigned __int128)udiv[1][0] << 64) | udiv[0][0];
    unsigned __int128 y = ((unsigned __int128)udiv[2][0] << 64) | udiv[1][0];
    unsigned __int128 s = x + y, d = x - y;
    label("u128");
    print(" "); print_hex((unsigned long long)(s >> 64)); print(" "); print_hex((unsigned long long)s);
    print(" "); print_hex((unsigned long long)(d >> 64)); print(" "); print_hex((unsigned long long)d);
    nl();

    label("not");
    print(" "); print_hex(~udiv[0][0]);
    nl();

    label("switch");
    for (int i = -1; i <= 7; i++) { print(" "); print_i(classify(i)); }
    nl();

    unsigned long long cell = 0x1111;
    unsigned long long old = swap_xchg(0x2222, &cell);
    label("xchg");
    print(" "); print_hex(old); print(" "); print_hex(cell);
    nl();

    unsigned char a[16], b[16];
    fill(a, 'x', 16);
    for (int i = 0; i < 16; i++) b[i] = (unsigned char)('a' + i);
    copy(a + 4, b, 8);
    label("rep");
    print(" "); put((const char *)a, 16);
    nl();

    ExitProcess((unsigned)(check & 0xff));
}
