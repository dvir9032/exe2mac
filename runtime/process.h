/* Per-process Windows state that lives outside the guest CPU: the process
 * heap, the command line, the thread's last-error value and VirtualAlloc
 * regions. All guest-visible memory is guest memory (bounds-checked). */
#ifndef EXE2MAC_PROCESS_H
#define EXE2MAC_PROCESS_H
#include <stdint.h>
#include "guest_heap.h"

#define EXE2MAC_HEAP_BASE      0x0000000020000000ull
#define EXE2MAC_HEAP_SIZE      (64ull * 1024 * 1024)
#define EXE2MAC_HEAP_HANDLE    EXE2MAC_HEAP_BASE      /* value returned by GetProcessHeap */
#define EXE2MAC_VALLOC_BASE    0x0000000030000000ull
#define EXE2MAC_VALLOC_LIMIT   0x0000000070000000ull
#define EXE2MAC_VALLOC_GRANULE 0x10000ull              /* allocation granularity: 64 KiB */
#define EXE2MAC_MAX_VREGIONS   32

/* Win32 error codes used by the bridges */
#define WIN_ERROR_INVALID_HANDLE     6u
#define WIN_ERROR_NOT_ENOUGH_MEMORY  8u
#define WIN_ERROR_READ_FAULT         30u
#define WIN_ERROR_INVALID_PARAMETER  87u

typedef struct exe2mac_process {
    guest_mem *mem;
    guest_heap heap;
    uint32_t last_error;
    uint64_t cmdline_va;
    uint64_t valloc_next;
    struct { uint64_t va, size; uint8_t *host; } vregions[EXE2MAC_MAX_VREGIONS];
    unsigned nvregions;
} exe2mac_process;

extern exe2mac_process g_exe2mac_proc;

/* Maps the heap and stores the command line built from argv (Windows quoting). */
int exe2mac_process_init(guest_mem *m, int argc, char **argv);

/* Windows command-line quoting of one argument (CommandLineToArgvW inverse).
 * Writes at most cap bytes (no NUL); returns the full length needed. */
uint64_t exe2mac_quote_arg(const char *arg, char *out, uint64_t cap);
#endif
