// Fixture 9: which Windows status code ends the process for each unmasked
// SSE floating-point exception. The first command-line argument selects the
// case; every case ends with an unhandled #XM (the process exit code is the
// NTSTATUS). test/xm.windows.bat runs all cases on Windows.
//   0 IE (0/0)          1 DE (denormal + 1)   2 ZE (1/0)
//   3 OE (max * 2)      4 UE (tiny * tiny)    5 PE (1/3)
//   6 all unmasked, max * 2 (OE and PE together)
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) char *__stdcall GetCommandLineA(void);

int _fltused = 0;

__attribute__((noinline)) static void trap(unsigned csr, unsigned long long a, unsigned long long b, int mul) {
    unsigned long long r;
    if (mul)
        __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; mulsd %%xmm1, %%xmm0; movq %%xmm0, %0"
                         : "=r"(r) : "r"(a), "r"(b), "m"(csr) : "xmm0", "xmm1", "memory");
    else
        __asm__ volatile("ldmxcsr %3; movq %1, %%xmm0; movq %2, %%xmm1; divsd %%xmm1, %%xmm0; movq %%xmm0, %0"
                         : "=r"(r) : "r"(a), "r"(b), "m"(csr) : "xmm0", "xmm1", "memory");
    (void)r;
}

void start(void) {
    const char *p = GetCommandLineA();
    // skip the program name (quoted or not), then spaces
    if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; }
    else while (*p && *p != ' ' && *p != '\t') p++;
    while (*p == ' ' || *p == '\t') p++;
    int c = (*p >= '0' && *p <= '9') ? *p - '0' : -1;

    HANDLE out = GetStdHandle((DWORD)-11);
    DWORD w;
    WriteFile(out, "trapping\n", 9, &w, 0);
    const unsigned DEF = 0x1F80u;
    switch (c) {
    case 0: trap(DEF & ~0x080u, 0, 0, 0); break;                                         /* IM */
    case 1: trap(DEF & ~0x100u, 0x0000000000000001ull, 0x3FF0000000000000ull, 1); break; /* DM */
    case 2: trap(DEF & ~0x200u, 0x3FF0000000000000ull, 0, 0); break;                     /* ZM */
    case 3: trap(DEF & ~0x400u, 0x7FEFFFFFFFFFFFFFull, 0x4000000000000000ull, 1); break; /* OM */
    case 4: trap(DEF & ~0x800u, 0x0010000000000000ull, 0x3E00000000000000ull, 1); break; /* UM */
    case 5: trap(DEF & ~0x1000u, 0x3FF0000000000000ull, 0x4008000000000000ull, 0); break;/* PM */
    case 6: trap(0x0000u, 0x7FEFFFFFFFFFFFFFull, 0x4000000000000000ull, 1); break;       /* all */
    default: break;
    }
    WriteFile(out, "no trap\n", 8, &w, 0);
    ExitProcess(99);
}
