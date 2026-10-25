// Fixture 5: program input and memory APIs without a C runtime.
// Reads all of stdin with ReadFile into a growing HeapAlloc/HeapReAlloc buffer,
// parses GetCommandLineA with the Windows argv rules, uses VirtualAlloc, and
// checks GetLastError/SetLastError. The program name (argv[0]) is not printed
// because it depends on how the program was started.
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned long long SIZE_T;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) char *__stdcall GetCommandLineA(void);
__declspec(dllimport) HANDLE __stdcall GetProcessHeap(void);
__declspec(dllimport) void *__stdcall HeapAlloc(HANDLE, DWORD, SIZE_T);
__declspec(dllimport) void *__stdcall HeapReAlloc(HANDLE, DWORD, void *, SIZE_T);
__declspec(dllimport) BOOL __stdcall HeapFree(HANDLE, DWORD, void *);
__declspec(dllimport) void *__stdcall VirtualAlloc(void *, SIZE_T, DWORD, DWORD);
__declspec(dllimport) BOOL __stdcall VirtualFree(void *, SIZE_T, DWORD);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD);

#define HEAP_ZERO_MEMORY 0x8
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04

static HANDLE out;
static void put(const char *s, unsigned long long n) { DWORD w; WriteFile(out, s, (DWORD)n, &w, 0); }
static void print(const char *s) { unsigned long long n = 0; while (s[n]) n++; put(s, n); }
static void print_u(unsigned long long u) {
    char buf[24];
    int i = 24;
    do { buf[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    put(buf + i, (unsigned long long)(24 - i));
}

// Windows (CommandLineToArgvW / MSVCRT) argument rules: 2n backslashes + quote
// -> n backslashes and toggle quoting; 2n+1 backslashes + quote -> n
// backslashes + literal quote; backslashes not before a quote are literal.
static int next_arg(const char **pp, char *dst) {
    const char *p = *pp;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) { *pp = p; return 0; }
    int inq = 0, n = 0;
    for (;;) {
        int bs = 0;
        while (*p == '\\') { p++; bs++; }
        if (*p == '"') {
            for (int k = 0; k < bs / 2; k++) dst[n++] = '\\';
            if (bs % 2) { dst[n++] = '"'; p++; }
            else if (inq && p[1] == '"') { dst[n++] = '"'; p += 2; }
            else { inq = !inq; p++; }
            continue;
        }
        for (int k = 0; k < bs; k++) dst[n++] = '\\';
        if (!*p || (!inq && (*p == ' ' || *p == '\t'))) break;
        dst[n++] = *p++;
    }
    dst[n] = 0;
    *pp = p;
    return 1;
}

void start(void) {
    out = GetStdHandle((DWORD)-11);
    HANDLE in = GetStdHandle((DWORD)-10);
    HANDLE heap = GetProcessHeap();

    // --- command line: skip the program name, print the rest ---
    const char *cl = GetCommandLineA();
    char *arg = HeapAlloc(heap, 0, 4096);
    unsigned nargs = 0;
    // The program name is parsed with the same rules but never printed.
    next_arg(&cl, arg);
    print("args:");
    while (next_arg(&cl, arg)) { print(" ["); print(arg); print("]"); nargs++; }
    print("\n");

    // --- stdin through a growing heap buffer ---
    unsigned long long cap = 16, len = 0;
    char *buf = HeapAlloc(heap, 0, cap);
    for (;;) {
        if (len == cap) { cap *= 2; buf = HeapReAlloc(heap, 0, buf, cap); }
        DWORD got = 0;
        if (!ReadFile(in, buf + len, (DWORD)(cap - len), &got, 0)) { print("read error\n"); break; }
        if (got == 0) break;
        len += got;
    }
    unsigned long long lines = 0, words = 0, sum = 0;
    int inword = 0;
    for (unsigned long long i = 0; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];
        sum = sum * 31 + c;
        if (c == '\n') lines++;
        if (c == ' ' || c == '\n' || c == '\t' || c == '\r') inword = 0;
        else if (!inword) { inword = 1; words++; }
    }
    print("stdin: bytes="); print_u(len); print(" lines="); print_u(lines);
    print(" words="); print_u(words); print(" hash="); print_u(sum & 0xffffffffu); print("\n");
    print("reversed first line: ");
    unsigned long long e = 0;
    while (e < len && buf[e] != '\n') e++;
    for (unsigned long long i = e; i > 0; i--) put(buf + i - 1, 1);
    print("\n");

    // --- heap properties ---
    unsigned char *z = HeapAlloc(heap, HEAP_ZERO_MEMORY, 1000);
    int zero = 1;
    for (int i = 0; i < 1000; i++) zero &= z[i] == 0;
    void *a = HeapAlloc(heap, 0, 1), *b = HeapAlloc(heap, 0, 1);
    print("heap: zeroed="); print_u((unsigned)zero);
    print(" aligned16="); print_u((unsigned)((((unsigned long long)z | (unsigned long long)a | (unsigned long long)b) & 15) == 0));
    print(" distinct="); print_u((unsigned)(a != b));
    print(" free="); print_u((unsigned)(HeapFree(heap, 0, a) && HeapFree(heap, 0, b) && HeapFree(heap, 0, z)));
    print("\n");

    // --- VirtualAlloc ---
    unsigned char *v = VirtualAlloc(0, 300000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    int vzero = 1;
    for (int i = 0; i < 300000; i += 4096) vzero &= v[i] == 0;
    v[299999] = 0x5a;
    print("virtual: ok="); print_u((unsigned)(v != 0));
    print(" aligned64k="); print_u((unsigned)(((unsigned long long)v & 0xffff) == 0));
    print(" zeroed="); print_u((unsigned)vzero);
    print(" last="); print_u(v[299999]);
    print(" release="); print_u((unsigned)VirtualFree(v, 0, MEM_RELEASE));
    print("\n");

    // --- last error ---
    SetLastError(1234);
    DWORD e1 = GetLastError();
    DWORD w;
    BOOL ok = WriteFile((HANDLE)0x1234, "x", 1, &w, 0);
    DWORD e2 = GetLastError();
    print("lasterror: set="); print_u(e1); print(" badwrite="); print_u((unsigned)ok);
    print(" err="); print_u(e2); print(" written="); print_u(w); print("\n");

    HeapFree(heap, 0, buf);
    HeapFree(heap, 0, arg);
    ExitProcess(nargs);
}
