#include "winapi_shims.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/* Windows constants: STD_INPUT_HANDLE=-10, STD_OUTPUT_HANDLE=-11,
 * STD_ERROR_HANDLE=-12. Values are represented as unsigned 32-bit inputs.
 */
uintptr_t exe2mac_GetStdHandle(uint32_t standard_handle) {
    if (standard_handle == (uint32_t)-11) return (uintptr_t)STDOUT_FILENO;
    if (standard_handle == (uint32_t)-12) return (uintptr_t)STDERR_FILENO;
    if (standard_handle == (uint32_t)-10) return (uintptr_t)STDIN_FILENO;
    return 0;
}

int32_t exe2mac_WriteFile(uintptr_t handle, const void *buffer,
                          uint32_t bytes_to_write, uint32_t *bytes_written,
                          void *overlapped) {
    (void)overlapped;
    if (bytes_written) *bytes_written = 0;
    if (handle > (uintptr_t)INT32_MAX || (!buffer && bytes_to_write != 0))
        return 0;
    const unsigned char *p = (const unsigned char *)buffer;
    uint32_t total = 0;
    while (total < bytes_to_write) {
        ssize_t n = write((int)handle, p + total, (size_t)(bytes_to_write - total));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (bytes_written) *bytes_written = total;
            return 0;
        }
        total += (uint32_t)n;
    }
    if (bytes_written) *bytes_written = total;
    return 1;
}

_Noreturn void exe2mac_ExitProcess(uint32_t exit_code) {
    exit((int)(exit_code & 0xffu));
}
