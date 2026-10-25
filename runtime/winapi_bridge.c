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
#include <string.h>

#include "exe2mac_rt.h"
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
    if (written_va) guest_st32(s->mem, written_va, written);
    guest_ret(s, (uint32_t)ok);          /* BOOL in EAX; 32-bit result zero-extended */
}

/* DECLSPEC_NORETURN VOID ExitProcess(UINT uExitCode) */
static void bridge_ExitProcess(x86_state *s) {
    exe2mac_ExitProcess((uint32_t)s->gpr[X86_RCX]);
}

const exe2mac_bridge exe2mac_bridges[] = {
    {"kernel32.dll", "ExitProcess", bridge_ExitProcess},
    {"kernel32.dll", "GetStdHandle", bridge_GetStdHandle},
    {"kernel32.dll", "WriteFile", bridge_WriteFile},
};
const unsigned exe2mac_nbridges = sizeof exe2mac_bridges / sizeof exe2mac_bridges[0];

int exe2mac_find_bridge(const char *dll, const char *name) {
    for (unsigned i = 0; i < exe2mac_nbridges; i++)
        if (strcmp(exe2mac_bridges[i].dll, dll) == 0 && strcmp(exe2mac_bridges[i].name, name) == 0)
            return (int)i;
    return -1;
}
