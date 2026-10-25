// Fixture 7: tail calls (clang -O2 turns calls in tail position into `jmp`).
//  - direct mutual tail recursion, one million levels deep: the GUEST stack
//    does not grow, so the translation must not grow the HOST stack either;
//  - tail calls to imports (`jmp [IAT]`), including the no-return ExitProcess;
//  - indirect tail calls through function pointers (`jmp reg`), both from
//    `lea reg, [rip + func]` and from a pointer table in .rdata, again deep.
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD);

static HANDLE out;
static void put(const char *s, unsigned long long n) { DWORD w; WriteFile(out, s, (DWORD)n, &w, 0); }
static void print(const char *s) { unsigned long long n = 0; while (s[n]) n++; put(s, n); }
static void print_u(unsigned long long u) {
    char buf[24];
    int i = 24;
    do { buf[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    put(buf + i, (unsigned long long)(24 - i));
}

static volatile int depth = 1000001;

__attribute__((noinline)) static int is_odd(unsigned n);
__attribute__((noinline)) static int is_even(unsigned n) { return n == 0 ? 1 : is_odd(n - 1); }
__attribute__((noinline)) static int is_odd(unsigned n) { return n == 0 ? 0 : is_even(n - 1); }

// tail call into an import
__attribute__((noinline)) static DWORD last_error(void) { return GetLastError(); }
__attribute__((noinline)) static void quit(unsigned code) { ExitProcess(code); }

// indirect tail calls
typedef unsigned long long (*fn_t)(unsigned long long, unsigned long long);
__attribute__((noinline)) static unsigned long long sq_add(unsigned long long x, unsigned long long acc) { return acc + x * x; }
__attribute__((noinline)) static unsigned long long apply(fn_t f, unsigned long long x) { return f(x, 1); }

__attribute__((noinline)) static unsigned long long st_a(unsigned long long n, unsigned long long acc);
__attribute__((noinline)) static unsigned long long st_b(unsigned long long n, unsigned long long acc);
static fn_t const machine[2] = { st_a, st_b };
static unsigned long long st_a(unsigned long long n, unsigned long long acc) {
    return n == 0 ? acc : machine[n & 1](n - 1, acc * 3 + 1);
}
static unsigned long long st_b(unsigned long long n, unsigned long long acc) {
    return n == 0 ? acc : machine[(n >> 1) & 1](n - 1, acc ^ (acc >> 7));
}

void start(void) {
    out = GetStdHandle((DWORD)-11);
    unsigned d = (unsigned)depth;
    print("parity:"); print(" "); print_u((unsigned)is_even(d)); print(" "); print_u((unsigned)is_odd(d)); print("\n");
    SetLastError(4242);
    print("lasterror: "); print_u(last_error()); print("\n");
    fn_t volatile f = sq_add;
    print("apply: "); print_u(apply(f, 12)); print("\n");
    print("machine: "); print_u(st_a((unsigned long long)depth, 7)); print("\n");
    quit((unsigned)(is_odd(d) * 10 + 3));
}
