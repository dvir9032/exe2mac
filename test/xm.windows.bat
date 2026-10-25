@echo off
rem Reference runs of the ORIGINAL xm.exe: one unmasked SSE exception per case.
rem Writes "<case> <ERRORLEVEL>" lines (full NTSTATUS, signed decimal).
type nul > xm.win.codes
for %%c in (0 1 2 3 4 5 6) do (
  test\xm.exe %%c > nul 2> nul
  call echo %%c %%ERRORLEVEL%%>> xm.win.codes
)
exit /b 0
