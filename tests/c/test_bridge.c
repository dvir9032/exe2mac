/* Windows x64 ABI bridge tests: arguments in RCX/RDX/R8/R9 and on the guest
 * stack, return values in RAX, guest RET, and pointer validation.
 * Writes "bridge-ok\n" to stdout via the WriteFile bridge; the Python driver
 * checks stdout byte-for-byte. Fault cases run in child processes. */
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "runtime/exe2mac_rt.h"

static int failures, checks;
#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); checks++; if (_a != _b) { failures++; \
    fprintf(stderr, "%s:%d: %s == 0x%" PRIx64 ", expected 0x%" PRIx64 "\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)

#define STK 0x20000000ull
#define DATA 0x30000000ull
static uint8_t stack_mem[0x1000], data_mem[0x100], ro_mem[0x10];
static guest_mem m;
static x86_state s;

static void setup(void) {
    memset(&m, 0, sizeof m);
    memset(&s, 0, sizeof s);
    memset(stack_mem, 0, sizeof stack_mem);
    guest_map(&m, STK, sizeof stack_mem, stack_mem, GUEST_PERM_R | GUEST_PERM_W, "stack");
    guest_map(&m, DATA, sizeof data_mem, data_mem, GUEST_PERM_R | GUEST_PERM_W, "data");
    guest_map(&m, 0x40000000ull, sizeof ro_mem, ro_mem, GUEST_PERM_R, "ro");
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
    s.gpr[X86_RCX] = 0x1001; s.gpr[X86_RDX] = DATA; s.gpr[X86_R8] = 1; s.gpr[X86_R9] = 0x40000000ull;
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

int main(void) {
    test_get_std_handle();
    test_write_file();
    EQ(child(wf_bad_buffer), 0x05);
    EQ(child(wf_readonly_written), 0x05);
    EQ(child(wf_overlapped), 0x01);                           /* translator fault 0xE0000001 */
    EQ(child(exit_process), 7);
    EQ(child(bad_thunk), 0x01);
    fprintf(stderr, "checks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
