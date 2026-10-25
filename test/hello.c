// Test program: a tiny Windows x64 console app with no C runtime.
// Built as a real PE .exe, then fed to the recompiler.
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);

static HANDLE out;

static int len(const char *s) { int n = 0; while (s[n]) n++; return n; }

static void print(const char *s) {
    DWORD written;
    WriteFile(out, s, (DWORD)len(s), &written, 0);
}

static void print_num(long long v) {
    char buf[32];
    int i = 31, neg = v < 0;
    unsigned long long u = neg ? -(unsigned long long)v : (unsigned long long)v;
    buf[i] = 0;
    do { buf[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (neg) buf[--i] = '-';
    print(buf + i);
}

__attribute__((noinline)) static unsigned long long fib(int n) {
    return n < 2 ? (unsigned long long)n : fib(n - 1) + fib(n - 2);
}

typedef int (*op_t)(int, int);
__attribute__((noinline)) static int op_add(int a, int b) { return a + b; }
__attribute__((noinline)) static int op_mul(int a, int b) { return a * b; }
__attribute__((noinline)) static int op_sub(int a, int b) { return a - b; }
__attribute__((noinline)) static int op_div(int a, int b) { return a / b; }
static op_t ops[] = { op_add, op_mul, op_sub, op_div };
static const char *names[] = { " + ", " * ", " - ", " / " };

__attribute__((noinline)) static void sort(int *a, int n) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j + 1 < n - i; j++)
            if (a[j] > a[j + 1]) { int t = a[j]; a[j] = a[j + 1]; a[j + 1] = t; }
}

void start(void) {
    out = GetStdHandle((DWORD)-11);
    print("Hello from a recompiled Windows exe!\n");

    print("fib: ");
    for (int i = 0; i <= 20; i += 4) { print_num((long long)fib(i)); print(" "); }
    print("\n");

    for (int k = 0; k < 4; k++) {
        print_num(84); print(names[k]); print_num(-4); print(" = ");
        print_num(ops[k](84, -4)); print("\n");
    }

    int arr[] = { 42, -7, 19, 3, 88, 0, -50, 11 };
    sort(arr, 8);
    print("sorted:");
    for (int i = 0; i < 8; i++) { print(" "); print_num(arr[i]); }
    print("\n");

    ExitProcess(7);
}
