@echo off
rem Reference run of the ORIGINAL mxcsr.exe. It ends with an unmasked SIMD
rem floating-point exception; the full NTSTATUS is written to mxcsr.win.code
rem because shells may map exception codes to signals.
test\mxcsr.exe > mxcsr.win.stdout 2> mxcsr.win.stderr
echo %ERRORLEVEL%> mxcsr.win.code
exit /b 0
