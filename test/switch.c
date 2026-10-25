// Fixture 3: dense switch statements that compile to jump tables
// (indirect `jmp` through a table of offsets in .rdata).
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);

static HANDLE out;
static void put(const char *s, int n) { DWORD w; WriteFile(out, s, (DWORD)n, &w, 0); }
static void print(const char *s) { int n = 0; while (s[n]) n++; put(s, n); }
static void print_i(long long v) {
    char buf[24];
    int i = 24, neg = v < 0;
    unsigned long long u = neg ? 0 - (unsigned long long)v : (unsigned long long)v;
    do { buf[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (neg) buf[--i] = '-';
    put(buf + i, 24 - i);
}

static volatile int salt = 3;

__attribute__((noinline)) static long long op(int code, long long a, long long b) {
    switch (code) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return b ? a / b : 0;
    case 4: return b ? a % b : 0;
    case 5: return a & b;
    case 6: return a | b;
    case 7: return a ^ b;
    case 8: return a << (b & 63);
    case 9: return a >> (b & 63);
    case 10: return -a;
    case 11: return ~a;
    default: return 999;
    }
}

__attribute__((noinline)) static const char *day(unsigned d) {
    switch (d) {
    case 0: print("<"); return "sun";
    case 1: print("<"); return "mon";
    case 2: print("["); return "tue";
    case 3: print("["); return "wed";
    case 4: print("{"); return "thu";
    case 5: print("{"); return "fri";
    case 6: print("("); return "sat";
    }
    return "???";
}

__attribute__((noinline)) static int sparse(int x) {
    switch (x) {   // sparse values: usually a compare tree, not a table
    case 7: return 1;
    case 1000: return 2;
    case -50: return 3;
    case 123456: return 4;
    default: return 0;
    }
}

void start(void) {
    out = GetStdHandle((DWORD)-11);
    long long acc = 0;
    print("op:");
    for (int c = -1; c <= 12; c++) {
        long long r = op(c, 1000 + salt, -7 + salt);
        print(" "); print_i(r);
        acc += r;
    }
    print("\nday:");
    for (unsigned d = 0; d < 9; d++) { print(" "); print(day(d)); }
    print("\nsparse:");
    int probes[] = { 7, 1000, -50, 123456, 8, 0 };
    for (int i = 0; i < 6; i++) { print(" "); print_i(sparse(probes[i])); acc += sparse(probes[i]); }
    print("\n");
    ExitProcess((unsigned)(acc & 0x7f));
}
