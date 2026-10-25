#include "process.h"

#include <stdio.h>
#include <string.h>

exe2mac_process g_exe2mac_proc;

static void emit(char *out, uint64_t cap, uint64_t *n, char c) {
    if (*n < cap) out[*n] = c;
    (*n)++;
}

uint64_t exe2mac_quote_arg(const char *arg, char *out, uint64_t cap) {
    uint64_t n = 0;
    int need = *arg == 0 || strpbrk(arg, " \t\n\v\"") != NULL;
    if (!need) {
        for (const char *p = arg; *p; p++) emit(out, cap, &n, *p);
        return n;
    }
    emit(out, cap, &n, '"');
    for (const char *p = arg;; p++) {
        uint64_t bs = 0;
        while (*p == '\\') { p++; bs++; }
        if (*p == 0) {                       /* backslashes before the closing quote are doubled */
            for (uint64_t k = 0; k < 2 * bs; k++) emit(out, cap, &n, '\\');
            break;
        }
        if (*p == '"') {                     /* 2n+1 backslashes then a literal quote */
            for (uint64_t k = 0; k < 2 * bs + 1; k++) emit(out, cap, &n, '\\');
        } else {
            for (uint64_t k = 0; k < bs; k++) emit(out, cap, &n, '\\');
        }
        emit(out, cap, &n, *p);
    }
    emit(out, cap, &n, '"');
    return n;
}

int exe2mac_process_init(guest_mem *m, int argc, char **argv) {
    exe2mac_process *p = &g_exe2mac_proc;
    memset(p, 0, sizeof *p);
    p->mem = m;
    p->valloc_next = EXE2MAC_VALLOC_BASE;
    if (guest_heap_init(&p->heap, m, EXE2MAC_HEAP_BASE, EXE2MAC_HEAP_SIZE)) {
        fprintf(stderr, "exe2mac: cannot create the guest heap\n");
        return -1;
    }
    uint64_t len = 0;
    for (int i = 0; i < argc; i++) len += exe2mac_quote_arg(argv[i], NULL, 0) + (i > 0);
    uint64_t va = guest_heap_alloc(&p->heap, len + 1, 1);
    if (!va) return -1;
    char *dst = (char *)guest_ptr(m, va, len + 1, GUEST_PERM_W);
    uint64_t pos = 0;
    for (int i = 0; i < argc; i++) {
        if (i > 0) dst[pos++] = ' ';
        pos += exe2mac_quote_arg(argv[i], dst + pos, len - pos);
    }
    dst[pos] = 0;
    p->cmdline_va = va;
    return 0;
}
