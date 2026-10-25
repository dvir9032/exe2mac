/* Fatal guest faults.
 *
 * A Windows process killed by an unhandled exception exits with the NTSTATUS
 * code (e.g. 0xC0000005 for an access violation). POSIX exit statuses carry
 * only 8 bits, so the host exit status is the low byte of the NTSTATUS. The full
 * code is printed to stderr, which never mixes with the guest's stdout.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "x86_cpu.h"

#define EXE2MAC_STATUS_ACCESS_VIOLATION 0xC0000005u
#define EXE2MAC_STATUS_TRANSLATOR_FAULT 0xE0000001u   /* customer-defined code */

static _Noreturn void die(uint32_t status, const char *msg, uint64_t a, uint64_t b, const x86_state *s) {
    fprintf(stderr, "exe2mac: fatal guest fault 0x%08" PRIx32 ": %s (0x%" PRIx64 ", 0x%" PRIx64 ")",
            status, msg, a, b);
    if (s) fprintf(stderr, " rip=0x%" PRIx64 " rsp=0x%" PRIx64, s->rip, s->gpr[X86_RSP]);
    fputc('\n', stderr);
    fflush(stderr);
    _exit((int)(status & 0xffu));
}

_Noreturn void exe2mac_mem_fault(uint64_t va, uint64_t len, unsigned need) {
    die(EXE2MAC_STATUS_ACCESS_VIOLATION,
        (need & GUEST_PERM_W) ? "invalid guest write" : "invalid guest read", va, len, NULL);
}

_Noreturn void exe2mac_raise(const x86_state *s, uint32_t ntstatus, const char *what) {
    die(ntstatus, what, 0, 0, s);
}

_Noreturn void exe2mac_fault(const x86_state *s, const char *what, uint64_t detail) {
    die(EXE2MAC_STATUS_TRANSLATOR_FAULT, what, detail, 0, s);
}
