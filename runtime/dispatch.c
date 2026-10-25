/* Run-time dispatch for guest control transfers that leave translated code:
 * import thunks, and diagnostics for return-address mismatches. */
#include <inttypes.h>
#include <stdio.h>

#include "exe2mac_rt.h"

void exe2mac_dispatch_external(x86_state *s, uint64_t target) {
    if (target >= EXE2MAC_THUNK_BASE) {
        uint64_t off = target - EXE2MAC_THUNK_BASE;
        if (off % EXE2MAC_THUNK_STRIDE == 0 && off / EXE2MAC_THUNK_STRIDE < exe2mac_nbridges) {
            exe2mac_bridges[off / EXE2MAC_THUNK_STRIDE].fn(s);
            return;
        }
    }
    exe2mac_fault(s, "call to a guest address with no translated code", target);
}

_Noreturn void exe2mac_bad_return(x86_state *s, uint64_t expected) {
    fprintf(stderr, "exe2mac: guest returned to 0x%" PRIx64 ", expected 0x%" PRIx64 "\n", s->rip, expected);
    exe2mac_fault(s, "guest return address mismatch", expected);
}

_Noreturn void exe2mac_noreturn_returned(x86_state *s, uint64_t call_site) {
    exe2mac_fault(s, "a no-return import returned", call_site);
}
