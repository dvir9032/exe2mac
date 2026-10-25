/* Windows x64 ABI bridge tests: arguments in RCX/RDX/R8/R9 and on the guest
 * stack, return values in RAX, guest RET, and pointer validation.
 * Writes "bridge-ok\n" to stdout via the WriteFile bridge; the Python driver
 * checks stdout byte-for-byte. Fault cases run in child processes. */
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

#include "runtime/exe2mac_rt.h"
#include "runtime/process.h"

/* the bridge tests link the runtime without a generated program: no imports */
const exe2mac_import exe2mac_imports[1] = {{0, 0, 0}};
const unsigned exe2mac_nimports = 0;

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); checks++; if (_a != _b) { failures++; \
    fprintf(stderr, "%s:%d: %s == 0x%" PRIx64 ", expected 0x%" PRIx64 "\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)

#define STK 0x11000000ull
#define DATA 0x12000000ull
static uint8_t stack_mem[0x1000], data_mem[0x100], ro_mem[0x10];
static guest_mem m;
static x86_state s;

static void setup(void) {
    if (g_exe2mac_proc.heap.host) guest_heap_destroy(&g_exe2mac_proc.heap, &m);
    for (unsigned i = 0; i < g_exe2mac_proc.nvregions; i++) free(g_exe2mac_proc.vregions[i].host);
    g_exe2mac_proc.nvregions = 0;
    memset(&m, 0, sizeof m);
    memset(&s, 0, sizeof s);
    memset(stack_mem, 0, sizeof stack_mem);
    guest_map(&m, STK, sizeof stack_mem, stack_mem, GUEST_PERM_R | GUEST_PERM_W, "stack");
    guest_map(&m, DATA, sizeof data_mem, data_mem, GUEST_PERM_R | GUEST_PERM_W, "data");
    guest_map(&m, 0x13000000ull, sizeof ro_mem, ro_mem, GUEST_PERM_R, "ro");
    s.mem = &m;
    s.gpr[X86_RSP] = STK + 0x800;
}

/* Emulate the guest side of a call: arg5 at [rsp+0x20] before the CALL,
 * then the CALL pushes the return address. */
static void guest_call(const char *name, uint64_t arg5, uint64_t ret_va) {
    guest_st64(&m, s.gpr[X86_RSP] + 0x20, arg5);
    x86_push64(&s, ret_va);
    int idx = exe2mac_find_bridge("kernel32.dll", name);
    if (idx < 0) { failures++; fprintf(stderr, "no bridge %s\n", name); return; }
    exe2mac_dispatch_external(&s, EXE2MAC_THUNK_BASE + (uint64_t)idx * EXE2MAC_THUNK_STRIDE);
}

static void test_get_std_handle(void) {
    setup();
    s.gpr[X86_RCX] = 0xdeadbeef00000000ull | (uint32_t)-11;  /* upper bits are garbage by ABI */
    s.gpr[X86_R12] = 0x1212;                                  /* callee-saved: untouched */
    guest_call("GetStdHandle", 0, 0x140001234ull);
    EQ(s.rip, 0x140001234ull);
    EQ(s.gpr[X86_RSP], STK + 0x800);                          /* RET popped the return address */
    EQ(s.gpr[X86_RAX], 0x1001);                               /* stdout handle = fd 1 + bias */
    EQ(s.gpr[X86_R12], 0x1212);
    s.gpr[X86_RCX] = 5;
    guest_call("GetStdHandle", 0, 0x140001234ull);
    EQ(s.gpr[X86_RAX], ~0ull);                                /* INVALID_HANDLE_VALUE */
}

static void test_write_file(void) {
    setup();
    memcpy(data_mem, "bridge-ok\nXXXX", 14);
    guest_st32(&m, DATA + 0x80, 0xffffffff);
    s.gpr[X86_RCX] = 0x1001;
    s.gpr[X86_RDX] = DATA;
    s.gpr[X86_R8] = 0xffffffff00000000ull | 10;               /* DWORD: only low 32 bits count */
    s.gpr[X86_R9] = DATA + 0x80;
    guest_call("WriteFile", 0, 0x140005678ull);
    EQ(s.gpr[X86_RAX], 1);
    EQ(guest_ld32(&m, DATA + 0x80), 10);
    EQ(s.rip, 0x140005678ull);
    EQ(s.gpr[X86_RSP], STK + 0x800);

    /* invalid handle -> FALSE, *written = 0 */
    s.gpr[X86_RCX] = 1;
    s.gpr[X86_R8] = 3;
    guest_call("WriteFile", 0, 0x140005678ull);
    EQ(s.gpr[X86_RAX], 0);
    EQ(guest_ld32(&m, DATA + 0x80), 0);

    /* NULL lpNumberOfBytesWritten is allowed when no OVERLAPPED is given */
    s.gpr[X86_RCX] = 0x1001; s.gpr[X86_R8] = 0; s.gpr[X86_R9] = 0;
    guest_call("WriteFile", 0, 0x140005678ull);
    EQ(s.gpr[X86_RAX], 1);
}

static int child(void (*fn)(void)) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        int dn = open("/dev/null", O_WRONLY);
        dup2(dn, 2); dup2(dn, 1);
        fn();
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st);
}

static void wf_bad_buffer(void) {
    setup();
    s.gpr[X86_RCX] = 0x1001; s.gpr[X86_RDX] = DATA + 0xf0; s.gpr[X86_R8] = 0x20; s.gpr[X86_R9] = 0;
    guest_call("WriteFile", 0, 0x140000000ull);               /* buffer runs past its region */
}
static void wf_readonly_written(void) {
    setup();
    s.gpr[X86_RCX] = 0x1001; s.gpr[X86_RDX] = DATA; s.gpr[X86_R8] = 1; s.gpr[X86_R9] = 0x13000000ull;
    guest_call("WriteFile", 0, 0x140000000ull);
}
static void wf_overlapped(void) {
    setup();
    s.gpr[X86_RCX] = 0x1001; s.gpr[X86_RDX] = DATA; s.gpr[X86_R8] = 1; s.gpr[X86_R9] = 0;
    guest_call("WriteFile", DATA, 0x140000000ull);
}
static void exit_process(void) {
    setup();
    s.gpr[X86_RCX] = 0xffffffff00000007ull;
    guest_call("ExitProcess", 0, 0x140000000ull);
    _exit(99);                                                /* must not be reached */
}
static void bad_thunk(void) {
    setup();
    x86_push64(&s, 0);
    exe2mac_dispatch_external(&s, EXE2MAC_THUNK_BASE + 8);    /* misaligned thunk VA */
}

static char *g_argv[] = {"prog name", "a\"b", "", NULL};

static void setup_proc(void) {
    setup();
    if (exe2mac_process_init(&m, 3, g_argv) != 0) { failures++; fprintf(stderr, "process init failed\n"); }
}

static uint64_t call4(const char *name, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    s.gpr[X86_RCX] = a; s.gpr[X86_RDX] = b; s.gpr[X86_R8] = c; s.gpr[X86_R9] = d;
    guest_call(name, 0, 0x140001000ull);
    EQ(s.rip, 0x140001000ull);
    EQ(s.gpr[X86_RSP], STK + 0x800);
    return s.gpr[X86_RAX];
}

static void test_cmdline_and_last_error(void) {
    setup_proc();
    uint64_t va = call4("GetCommandLineA", 0, 0, 0, 0);
    const char *want = "\"prog name\" \"a\\\"b\" \"\"";
    const char *got = (const char *)guest_ptr(&m, va, strlen(want) + 1, GUEST_PERM_R);
    checks++;
    if (strcmp(got, want)) { failures++; fprintf(stderr, "command line '%s' != '%s'\n", got, want); }
    EQ(call4("GetCommandLineA", 0, 0, 0, 0), va);              /* same pointer every time */
    call4("SetLastError", 0xdeadbeef00000000ull | 1234, 0, 0, 0); /* DWORD: low 32 bits */
    EQ(call4("GetLastError", 0, 0, 0, 0), 1234);
}

static void test_heap_bridges(void) {
    setup_proc();
    uint64_t heap = call4("GetProcessHeap", 0, 0, 0, 0);
    EQ(heap, EXE2MAC_HEAP_HANDLE);
    uint64_t p = call4("HeapAlloc", heap, 8, 40, 0);
    CHECK(p != 0); EQ(p & 15, 0);
    EQ(guest_ld64(&m, p + 32), 0);
    guest_st8(&m, p, 0x42);
    uint64_t q = call4("HeapReAlloc", heap, 8, p, 4000);
    CHECK(q != 0);
    EQ(guest_ld8(&m, q), 0x42);
    EQ(guest_ld64(&m, q + 3992), 0);
    EQ(call4("HeapFree", heap, 0, q, 0), 1);
    call4("SetLastError", 0, 0, 0, 0);
    EQ(call4("HeapFree", heap, 0, q, 0), 0);                    /* already freed */
    EQ(call4("GetLastError", 0, 0, 0, 0), 87);
    EQ(call4("HeapFree", heap, 0, 0, 0), 1);                    /* NULL: no-op success */
}

static void test_virtual_bridges(void) {
    setup_proc();
    uint64_t a = call4("VirtualAlloc", 0, 300000, 0x3000, 4);
    EQ(a, EXE2MAC_VALLOC_BASE);
    EQ(guest_ld8(&m, a + 299999), 0);
    guest_st8(&m, a + 299999, 9);
    uint64_t b = call4("VirtualAlloc", 0, 1, 0x3000, 4);
    EQ(b, EXE2MAC_VALLOC_BASE + 0x50000);                        /* 300000 -> 0x49400 -> next 64 KiB */
    EQ(call4("VirtualAlloc", 0, 0, 0x3000, 4), 0);
    EQ(call4("GetLastError", 0, 0, 0, 0), 87);
    EQ(call4("VirtualFree", a + 4096, 0, 0x8000, 0), 0);        /* not a region base */
    EQ(call4("VirtualFree", a, 0, 0x8000, 0), 1);
    CHECK(guest_try_ptr(&m, a, 1, GUEST_PERM_R) == NULL);       /* released */
    EQ(call4("VirtualFree", a, 0, 0x8000, 0), 0);
    uint64_t r = call4("VirtualAlloc", 0, 4096, 0x3000, 2);     /* PAGE_READONLY */
    CHECK(guest_try_ptr(&m, r, 1, GUEST_PERM_R) != NULL);
    CHECK(guest_try_ptr(&m, r, 1, GUEST_PERM_W) == NULL);
}

static void test_read_file(void) {
    setup_proc();
    uint64_t in = call4("GetStdHandle", (uint32_t)-10, 0, 0, 0);
    EQ(in, 0x1000);
    EQ(call4("ReadFile", in, DATA, 5, DATA + 0x80), 1);
    EQ(guest_ld32(&m, DATA + 0x80), 5);
    CHECK(memcmp(data_mem, "bridg", 5) == 0);
    EQ(call4("ReadFile", in, DATA, 0x40, DATA + 0x80), 1);     /* rest of input */
    EQ(guest_ld32(&m, DATA + 0x80), 7);
    CHECK(memcmp(data_mem, "e-input", 7) == 0);
    EQ(call4("ReadFile", in, DATA, 0x40, DATA + 0x80), 1);     /* end of input: TRUE, 0 bytes */
    EQ(guest_ld32(&m, DATA + 0x80), 0);
    EQ(call4("ReadFile", 0x1001, DATA, 4, DATA + 0x80), 0);    /* stdout is not readable here */
    EQ(call4("GetLastError", 0, 0, 0, 0), 6);
}

static void heap_bad_flags(void) { setup_proc(); call4("HeapAlloc", EXE2MAC_HEAP_HANDLE, 4, 8, 0); }
static void heap_bad_handle(void) { setup_proc(); call4("HeapAlloc", 0x1234, 0, 8, 0); }
static void valloc_fixed(void) { setup_proc(); call4("VirtualAlloc", 0x50000000, 4096, 0x3000, 4); }
static void valloc_exec(void) { setup_proc(); call4("VirtualAlloc", 0, 4096, 0x3000, 0x40); }
static void vfree_decommit(void) { setup_proc(); call4("VirtualFree", EXE2MAC_VALLOC_BASE, 4096, 0x4000, 0); }
static void valloc_use_after_free(void) {
    setup_proc();
    uint64_t a = call4("VirtualAlloc", 0, 4096, 0x3000, 4);
    call4("VirtualFree", a, 0, 0x8000, 0);
    guest_ld8(&m, a);
}
static void readonly_write(void) {
    setup_proc();
    uint64_t r = call4("VirtualAlloc", 0, 4096, 0x3000, 2);
    guest_st8(&m, r, 1);
}
static void read_overlapped(void) {
    setup_proc();
    s.gpr[X86_RCX] = 0x1000; s.gpr[X86_RDX] = DATA; s.gpr[X86_R8] = 1; s.gpr[X86_R9] = 0;
    guest_call("ReadFile", DATA, 0x140000000ull);
}

int main(void) {
    test_get_std_handle();
    test_write_file();
    EQ(child(wf_bad_buffer), 0x05);
    EQ(child(wf_readonly_written), 0x05);
    EQ(child(wf_overlapped), 0x01);                           /* translator fault 0xE0000001 */
    EQ(child(exit_process), 7);
    EQ(child(bad_thunk), 0x01);
    test_cmdline_and_last_error();
    test_heap_bridges();
    test_virtual_bridges();
    test_read_file();
    EQ(child(heap_bad_flags), 0x01);
    EQ(child(heap_bad_handle), 0x01);
    EQ(child(valloc_fixed), 0x01);
    EQ(child(valloc_exec), 0x01);
    EQ(child(vfree_decommit), 0x01);
    EQ(child(valloc_use_after_free), 0x05);
    EQ(child(readonly_write), 0x05);
    EQ(child(read_overlapped), 0x01);
    setup();                                         /* release heap/regions (leak checker) */
    fprintf(stderr, "checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
