/* Windows x64 ABI -> host bridges for imported functions.
 *
 * A bridge is entered exactly like a guest callee: the guest CALL has already
 * pushed its return address, so on entry
 *     RCX, RDX, R8, R9  = arguments 1-4
 *     [RSP]             = return address
 *     [RSP+0x08..0x28)  = caller-allocated home space
 *     [RSP+0x28]        = argument 5, [RSP+0x30] = argument 6, ...
 * The bridge reads arguments with their declared C widths (a DWORD uses only
 * the low 32 bits of its register; upper bits are garbage by ABI), converts
 * guest pointers through the bounds-checked guest memory layer, calls the
 * host shim, writes RAX, and performs the guest RET.
 *
 * Volatile registers (RCX, RDX, R8-R11) and the status flags are left as they
 * were; the ABI makes them undefined after a call, so this is a valid outcome.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "exe2mac_rt.h"
#include "process.h"
#include "winapi_shims.h"

/* Guest-visible handle values for the standard streams. Windows never hands out
 * NULL (0) as a valid handle, so the host fd is biased. */
#define EXE2MAC_HANDLE_BIAS 0x1000u
#define WIN_INVALID_HANDLE_VALUE (~(uint64_t)0)

static uint64_t arg_stack(x86_state *s, unsigned n) {   /* n >= 5, 1-based */
    return guest_ld64(s->mem, s->gpr[X86_RSP] + 8 + 8 * (uint64_t)(n - 1));
}

static void guest_ret(x86_state *s, uint64_t rax) {
    s->gpr[X86_RAX] = rax;
    s->rip = x86_pop64(s);
}

/* HANDLE GetStdHandle(DWORD nStdHandle) */
static void bridge_GetStdHandle(x86_state *s) {
    uint32_t which = (uint32_t)s->gpr[X86_RCX];
    uint64_t h = WIN_INVALID_HANDLE_VALUE;
    if (which == (uint32_t)-10 || which == (uint32_t)-11 || which == (uint32_t)-12)
        h = (uint64_t)exe2mac_GetStdHandle(which) + EXE2MAC_HANDLE_BIAS;
    guest_ret(s, h);
}

/* BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) */
static void bridge_WriteFile(x86_state *s) {
    uint64_t handle = s->gpr[X86_RCX];
    uint64_t buf = s->gpr[X86_RDX];
    uint32_t len = (uint32_t)s->gpr[X86_R8];
    uint64_t written_va = s->gpr[X86_R9];
    uint64_t overlapped = arg_stack(s, 5);

    if (overlapped != 0) exe2mac_fault(s, "WriteFile: OVERLAPPED I/O is not supported", overlapped);
    if (written_va) guest_st32(s->mem, written_va, 0);       /* Windows zeroes it first */

    int32_t ok = 0;
    uint32_t written = 0;
    if (handle >= EXE2MAC_HANDLE_BIAS && handle <= EXE2MAC_HANDLE_BIAS + 2) {
        const uint8_t *p = len ? guest_ptr(s->mem, buf, len, GUEST_PERM_R) : NULL;
        ok = exe2mac_WriteFile((uintptr_t)(handle - EXE2MAC_HANDLE_BIAS), p ? (const void *)p : (const void *)"",
                               len, &written, NULL);
    }
    else {
        g_exe2mac_proc.last_error = WIN_ERROR_INVALID_HANDLE;
    }
    if (written_va) guest_st32(s->mem, written_va, written);
    guest_ret(s, (uint32_t)ok);          /* BOOL in EAX; 32-bit result zero-extended */
}

/* BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) - standard input only.
 * Reads until the buffer is full or end of input (file semantics); returns
 * TRUE with 0 bytes at end of input. */
static void bridge_ReadFile(x86_state *s) {
    uint64_t handle = s->gpr[X86_RCX];
    uint64_t buf = s->gpr[X86_RDX];
    uint32_t len = (uint32_t)s->gpr[X86_R8];
    uint64_t read_va = s->gpr[X86_R9];
    uint64_t overlapped = arg_stack(s, 5);

    if (overlapped != 0) exe2mac_fault(s, "ReadFile: OVERLAPPED I/O is not supported", overlapped);
    if (read_va) guest_st32(s->mem, read_va, 0);
    if (handle != EXE2MAC_HANDLE_BIAS + 0) {
        g_exe2mac_proc.last_error = WIN_ERROR_INVALID_HANDLE;
        guest_ret(s, 0);
        return;
    }
    uint8_t *p = len ? guest_ptr(s->mem, buf, len, GUEST_PERM_W) : NULL;
    uint32_t total = 0;
    while (total < len) {
        ssize_t n = read(STDIN_FILENO, p + total, (size_t)(len - total));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            g_exe2mac_proc.last_error = WIN_ERROR_READ_FAULT;
            if (read_va) guest_st32(s->mem, read_va, total);
            guest_ret(s, 0);
            return;
        }
        if (n == 0) break;
        total += (uint32_t)n;
    }
    if (read_va) guest_st32(s->mem, read_va, total);
    guest_ret(s, 1);
}

/* LPSTR GetCommandLineA(void) */
static void bridge_GetCommandLineA(x86_state *s) { guest_ret(s, g_exe2mac_proc.cmdline_va); }

/* DWORD GetLastError(void) / VOID SetLastError(DWORD) */
static void bridge_GetLastError(x86_state *s) { guest_ret(s, g_exe2mac_proc.last_error); }
static void bridge_SetLastError(x86_state *s) {
    g_exe2mac_proc.last_error = (uint32_t)s->gpr[X86_RCX];
    guest_ret(s, s->gpr[X86_RAX]);      /* VOID: RAX is undefined; leave it unchanged */
}

/* ---- process heap ------------------------------------------------------ */
#define WIN_HEAP_NO_SERIALIZE   0x1u
#define WIN_HEAP_ZERO_MEMORY    0x8u

static void check_heap(x86_state *s, uint64_t heap, uint32_t flags, const char *fn) {
    if (heap != EXE2MAC_HEAP_HANDLE) exe2mac_fault(s, fn, heap);   /* only GetProcessHeap() is supported */
    if (flags & ~(WIN_HEAP_NO_SERIALIZE | WIN_HEAP_ZERO_MEMORY))
        exe2mac_fault(s, "heap call with unsupported flags (e.g. HEAP_GENERATE_EXCEPTIONS)", flags);
}

/* HANDLE GetProcessHeap(void) */
static void bridge_GetProcessHeap(x86_state *s) { guest_ret(s, EXE2MAC_HEAP_HANDLE); }

/* LPVOID HeapAlloc(HANDLE, DWORD dwFlags, SIZE_T dwBytes) */
static void bridge_HeapAlloc(x86_state *s) {
    uint32_t flags = (uint32_t)s->gpr[X86_RDX];
    check_heap(s, s->gpr[X86_RCX], flags, "HeapAlloc: unsupported heap handle");
    guest_ret(s, guest_heap_alloc(&g_exe2mac_proc.heap, s->gpr[X86_R8], (flags & WIN_HEAP_ZERO_MEMORY) != 0));
}

/* LPVOID HeapReAlloc(HANDLE, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) */
static void bridge_HeapReAlloc(x86_state *s) {
    uint32_t flags = (uint32_t)s->gpr[X86_RDX];
    check_heap(s, s->gpr[X86_RCX], flags, "HeapReAlloc: unsupported heap handle");
    guest_ret(s, guest_heap_realloc(&g_exe2mac_proc.heap, s->gpr[X86_R8], s->gpr[X86_R9],
                                    (flags & WIN_HEAP_ZERO_MEMORY) != 0));
}

/* BOOL HeapFree(HANDLE, DWORD dwFlags, LPVOID lpMem); NULL is a no-op success. */
static void bridge_HeapFree(x86_state *s) {
    check_heap(s, s->gpr[X86_RCX], (uint32_t)s->gpr[X86_RDX], "HeapFree: unsupported heap handle");
    uint64_t mem = s->gpr[X86_R8];
    if (mem == 0 || guest_heap_free(&g_exe2mac_proc.heap, mem)) { guest_ret(s, 1); return; }
    g_exe2mac_proc.last_error = WIN_ERROR_INVALID_PARAMETER;
    guest_ret(s, 0);
}

/* ---- virtual memory ---------------------------------------------------- */
#define WIN_MEM_COMMIT      0x1000u
#define WIN_MEM_RESERVE     0x2000u
#define WIN_MEM_DECOMMIT    0x4000u
#define WIN_MEM_RELEASE     0x8000u
#define WIN_MEM_TOP_DOWN    0x100000u
#define WIN_PAGE_READONLY   0x02u
#define WIN_PAGE_READWRITE  0x04u

/* LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
 * Supported: lpAddress == NULL, MEM_COMMIT|MEM_RESERVE (optionally MEM_TOP_DOWN),
 * PAGE_READWRITE or PAGE_READONLY. Memory is zeroed and 64 KiB aligned. */
static void bridge_VirtualAlloc(x86_state *s) {
    exe2mac_process *p = &g_exe2mac_proc;
    uint64_t addr = s->gpr[X86_RCX], size = s->gpr[X86_RDX];
    uint32_t type = (uint32_t)s->gpr[X86_R8], prot = (uint32_t)s->gpr[X86_R9];
    if (addr != 0) exe2mac_fault(s, "VirtualAlloc at a fixed address is not supported", addr);
    if ((type & ~WIN_MEM_TOP_DOWN) != (WIN_MEM_COMMIT | WIN_MEM_RESERVE))
        exe2mac_fault(s, "VirtualAlloc: only MEM_COMMIT|MEM_RESERVE is supported", type);
    if (prot != WIN_PAGE_READWRITE && prot != WIN_PAGE_READONLY)
        exe2mac_fault(s, "VirtualAlloc: unsupported page protection", prot);
    if (size == 0) { p->last_error = WIN_ERROR_INVALID_PARAMETER; guest_ret(s, 0); return; }
    uint64_t pages = (size + 0xfff) & ~(uint64_t)0xfff;
    uint64_t va = p->valloc_next;
    if (pages < size || p->nvregions == EXE2MAC_MAX_VREGIONS || va + pages < va || va + pages > EXE2MAC_VALLOC_LIMIT) {
        p->last_error = WIN_ERROR_NOT_ENOUGH_MEMORY;
        guest_ret(s, 0);
        return;
    }
    uint8_t *host = calloc(1, pages);
    unsigned perms = GUEST_PERM_R | (prot == WIN_PAGE_READWRITE ? GUEST_PERM_W : 0);
    if (!host || guest_map(s->mem, va, pages, host, perms, "VirtualAlloc")) {
        free(host);
        p->last_error = WIN_ERROR_NOT_ENOUGH_MEMORY;
        guest_ret(s, 0);
        return;
    }
    p->vregions[p->nvregions].va = va;
    p->vregions[p->nvregions].size = pages;
    p->vregions[p->nvregions].host = host;
    p->nvregions++;
    p->valloc_next = (va + pages + EXE2MAC_VALLOC_GRANULE - 1) & ~(EXE2MAC_VALLOC_GRANULE - 1);
    guest_ret(s, va);
}

/* BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) - MEM_RELEASE only */
static void bridge_VirtualFree(x86_state *s) {
    exe2mac_process *p = &g_exe2mac_proc;
    uint64_t addr = s->gpr[X86_RCX], size = s->gpr[X86_RDX];
    uint32_t type = (uint32_t)s->gpr[X86_R8];
    if (type != WIN_MEM_RELEASE) exe2mac_fault(s, "VirtualFree: only MEM_RELEASE is supported", type);
    for (unsigned i = 0; size == 0 && i < p->nvregions; i++) {
        if (p->vregions[i].va != addr) continue;
        guest_unmap(s->mem, addr);
        free(p->vregions[i].host);
        p->vregions[i] = p->vregions[--p->nvregions];
        guest_ret(s, 1);
        return;
    }
    p->last_error = WIN_ERROR_INVALID_PARAMETER;
    guest_ret(s, 0);
}

/* DECLSPEC_NORETURN VOID ExitProcess(UINT uExitCode) */
static void bridge_ExitProcess(x86_state *s) {
    exe2mac_ExitProcess((uint32_t)s->gpr[X86_RCX]);
}

const exe2mac_bridge exe2mac_bridges[] = {
    {"kernel32.dll", "ExitProcess", bridge_ExitProcess},
    {"kernel32.dll", "GetStdHandle", bridge_GetStdHandle},
    {"kernel32.dll", "WriteFile", bridge_WriteFile},
    {"kernel32.dll", "ReadFile", bridge_ReadFile},
    {"kernel32.dll", "GetCommandLineA", bridge_GetCommandLineA},
    {"kernel32.dll", "GetLastError", bridge_GetLastError},
    {"kernel32.dll", "SetLastError", bridge_SetLastError},
    {"kernel32.dll", "GetProcessHeap", bridge_GetProcessHeap},
    {"kernel32.dll", "HeapAlloc", bridge_HeapAlloc},
    {"kernel32.dll", "HeapReAlloc", bridge_HeapReAlloc},
    {"kernel32.dll", "HeapFree", bridge_HeapFree},
    {"kernel32.dll", "VirtualAlloc", bridge_VirtualAlloc},
    {"kernel32.dll", "VirtualFree", bridge_VirtualFree},
};
const unsigned exe2mac_nbridges = sizeof exe2mac_bridges / sizeof exe2mac_bridges[0];

int exe2mac_find_bridge(const char *dll, const char *name) {
    for (unsigned i = 0; i < exe2mac_nbridges; i++)
        if (strcmp(exe2mac_bridges[i].dll, dll) == 0 && strcmp(exe2mac_bridges[i].name, name) == 0)
            return (int)i;
    return -1;
}
