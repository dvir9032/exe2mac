# exe2mac — handoff to an AI coding agent

## Start here
1. Open the `exe2mac/` directory as the project/workspace in your coding agent (ChatGPT Work, Codex, Claude Code, Cursor, etc.).
2. Make sure the agent has permission to edit files and run local tests. Do not grant credentials or broad system permissions unless needed.
3. Paste the contents of `prompts/MASTER_PROMPT_HE.md` as the initial task, or tell the agent: `Read AGENTS.md and prompts/MASTER_PROMPT_HE.md completely and follow them.`
4. Let it work on Task 1 through Task 5 in `prompts/TASKS.md`. Require actual code edits and tests, not only a plan.
5. Ask for a progress report after each task and review the diff before accepting it.

## Baseline commands
```bash
python3 -m unittest discover -s tests -v
python3 -m recompiler.analyze_cli test/hello.exe -o hello-analysis.json
```

## Current baseline in the prepared environment
74 tests pass on Linux x86-64 (2026-10-25). `python3 -m recompiler run test/hello.exe --expect-stdout test/golden/hello.stdout --expect-exit 7`
builds and executes the translated program on the current host. Verified on macOS ARM64 via the
`macos-arm64` GitHub Actions workflow (see `STAGE3_STATUS.md`); locally use `sh scripts/verify_macos_arm64.sh`.

## Prompt for regular status updates
```text
Continue implementing exe2mac from the current repository state. Read AGENTS.md and prompts/TASKS.md. Make concrete code changes, run the relevant tests, and continue to the next scoped task. Do not stop after analysis. Report only verified results: exact files changed, commands run, test counts, target OS/architecture, whether a generated binary was built and actually executed, exact stdout comparison and exit status, and remaining blockers. Never claim macOS ARM64 runtime validation unless you actually ran it on macOS ARM64.
```


## Latest verified checkpoint

The current repository includes a byte-preserving descriptive instruction IR:
`recompiler/ir.py`, `recompiler/ir_cli.py`, and `test/hello-ir.json`.
Run `python3 -m unittest discover -s tests -v`; the expected current result is
10 passing tests on a host with Python, objdump, and a C compiler. This is still
not an end-to-end translator: `recompiler/translate.py` intentionally fails
closed, and native macOS ARM64 execution has not been verified.
