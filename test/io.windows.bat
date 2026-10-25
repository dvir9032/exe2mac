@echo off
rem Reference run of the ORIGINAL io.exe on Windows. The command line is passed
rem verbatim by cmd; redirections come first so the odd quote count of the
rem arguments cannot affect them.
< test\golden\io.input > io.win.stdout 2> io.win.stderr test\io.exe alpha "b c" q\"uote "back\slash\\" ""
exit /b %ERRORLEVEL%
