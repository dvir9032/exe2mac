# Golden output for test/hello.exe

`hello.stdout` (149 bytes, sha256 `37d9bd3aed0bb630037598a49e7e28780b658083cd50acf0ed9ca6ee541d34c2`) is the expected standard output;
the expected exit code is 7.

## Provenance
1. Derived by reading `test/hello.c`, written down in
   `docs/BASELINE_2026-10-25.md` before the translator existed.
2. **Confirmed on Windows** — GitHub Actions run 40183160790, job
   `windows-reference` (`windows-latest`, Microsoft Windows 10.0.26100, x86_64):
   the original `hello.exe` printed exactly these 149 bytes (same sha256),
   wrote nothing to stderr, and exited with code 7.

`.gitattributes` marks this directory `-text`: a Windows checkout with
`core.autocrlf` otherwise rewrites the file to CRLF (observed in run 40183093602).
