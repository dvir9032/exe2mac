# Golden output for test/hello.exe

`hello.stdout` (149 bytes) is the expected standard output; the expected exit
code is 7 (`ExitProcess(7)` in `test/hello.c`).

## Provenance — read this
The file was **derived by reading `test/hello.c`** (fib(0,4,…,20), the four
`ops[k](84, -4)` results, bubble sort of the array, exact spacing including the
trailing space on the `fib:` line). The derivation was written down in
`docs/BASELINE_2026-10-25.md` *before* the translator existed.

It has **not** been captured from a run of `hello.exe` on Windows; no Windows
host was available. When one is, run in `cmd.exe`:

    hello.exe > hello.windows.stdout
    echo %ERRORLEVEL%

then compare `hello.windows.stdout` with `hello.stdout` byte-for-byte and
replace this note with the result.

A host build of `hello.c` is not used as a substitute: it would bypass the PE
loader, the translator, the ABI bridge and IAT dispatch.
