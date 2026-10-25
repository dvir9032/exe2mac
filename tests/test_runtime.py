"""Compile and exercise the portable WinAPI host shims."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))

@unittest.skipUnless(shutil.which("cc"), "a C compiler is required")
class RuntimeShimTests(unittest.TestCase):
    def test_stdout_shim_writes_exact_bytes(self):
        source = r'''#include "runtime/winapi_shims.h"
#include <stdint.h>
int main(void) {
    const char s[] = "exe2mac-shim-ok\n";
    uint32_t n = 0;
    uintptr_t h = exe2mac_GetStdHandle((uint32_t)-11);
    if (!h && h != 0) return 2;
    if (!exe2mac_WriteFile(h, s, (uint32_t)(sizeof(s)-1), &n, 0)) return 3;
    return n == sizeof(s)-1 ? 0 : 4;
}
'''
        with tempfile.TemporaryDirectory() as td:
            cfile = os.path.join(td, "main.c")
            exe = os.path.join(td, "shim-test")
            with open(cfile, "w") as f:
                f.write(source)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", ROOT, cfile,
                            os.path.join(ROOT, "runtime", "winapi_shims.c"),
                            "-o", exe], check=True, capture_output=True)
            result = subprocess.run([exe], check=False, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, b"exe2mac-shim-ok\n")

if __name__ == "__main__":
    unittest.main()
