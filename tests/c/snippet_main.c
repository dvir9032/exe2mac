/* Test harness for lifted snippets: load the generated image, run the entry
 * function (which must end with RET), then print the final guest state. */
#include <inttypes.h>
#include <stdio.h>

#include "runtime/exe2mac_rt.h"
#include "runtime/process.h"

int main(int argc, char **argv) {
    static x86_state s;
    static guest_mem m;
    if (exe2mac_load(&s, &m, exe2mac_preferred_base) != 0) return 125;
    if (exe2mac_process_init(&m, argc, argv) != 0) return 125;
    uint64_t rsp0 = s.gpr[X86_RSP];
    exe2mac_dispatch(&s, s.rip);
    if (s.rip != EXE2MAC_EXIT_SENTINEL) exe2mac_bad_return(&s, EXE2MAC_EXIT_SENTINEL);
    static const char *names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    for (int i = 0; i < 16; i++) printf("%s=%" PRIx64 "\n", names[i], s.gpr[i]);
    printf("rsp_delta=%" PRId64 "\n", (int64_t)(s.gpr[X86_RSP] - rsp0));
    printf("cf=%d pf=%d af=%d zf=%d sf=%d of=%d\n", s.cf, s.pf, s.af, s.zf, s.sf, s.of);
    return 0;
}
