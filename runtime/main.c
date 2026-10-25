/* Process start-up for a translated program.
 *
 * EXE2MAC_IMAGE_BASE=<hex> loads the guest image at a non-preferred base,
 * which exercises the relocation path (testing aid; default = preferred base).
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "exe2mac_rt.h"
#include "process.h"
#include "winapi_shims.h"

int main(int argc, char **argv) {
    static x86_state s;
    static guest_mem m;
    uint64_t base = exe2mac_preferred_base;
    const char *env = getenv("EXE2MAC_IMAGE_BASE");
    if (env && *env) {
        char *end = NULL;
        base = strtoull(env, &end, 16);
        if (!end || *end) {
            fprintf(stderr, "exe2mac: invalid EXE2MAC_IMAGE_BASE '%s'\n", env);
            return 125;
        }
    }
    if (exe2mac_load(&s, &m, base) != 0) return 125;
    if (exe2mac_process_init(&m, argc, argv) != 0) return 125;

    exe2mac_dispatch(&s, s.rip);
    if (s.rip != EXE2MAC_EXIT_SENTINEL) exe2mac_bad_return(&s, EXE2MAC_EXIT_SENTINEL);
    /* Returning from the entry point ends the (only) thread; the process exit
     * code is the returned DWORD. POSIX keeps the low 8 bits. */
    exe2mac_ExitProcess((uint32_t)s.gpr[X86_RAX]);
}
