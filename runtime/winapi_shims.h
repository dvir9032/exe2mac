#ifndef EXE2MAC_WINAPI_SHIMS_H
#define EXE2MAC_WINAPI_SHIMS_H
#include <stddef.h>
#include <stdint.h>

/* Minimal host-side shims for the imports used by test/hello.exe.
 * Guest ABI adaptation (Windows x64 RCX/RDX/R8/R9 -> host C ABI) belongs
 * in the generated call wrapper, not in these host-native functions.
 */
#ifdef __cplusplus
extern "C" {
#endif

uintptr_t exe2mac_GetStdHandle(uint32_t standard_handle);
int32_t exe2mac_WriteFile(uintptr_t handle, const void *buffer,
                          uint32_t bytes_to_write, uint32_t *bytes_written,
                          void *overlapped);
_Noreturn void exe2mac_ExitProcess(uint32_t exit_code);

#ifdef __cplusplus
}
#endif
#endif
