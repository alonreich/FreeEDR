# Instructions for AI agents working on FreeEDR

**Start every session with [`project_structure.txt`](project_structure.txt).** It maps the repository and routes you to
only the docs your task needs. The full workflow is in [docs/agents/AGENT_WORKFLOW.md](docs/agents/AGENT_WORKFLOW.md).

Mandatory after **every** code change:
1. Run `dev_build.cmd` (through `cmd.exe`, full path). Every gate must pass.
2. Run, **unelevated**: `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1`
3. Look into every FAIL and WARN in `tests\results\last-run.txt`. Report the `TEST RESULT` line and every SKIP.
4. Add your entry to [`docs/CHANGELOG.md`](docs/CHANGELOG.md) under `## Unreleased`: a plain-English line under
   "What's new for you" (what users notice and why it matters, no jargon) and a line under "Technical". Every agent that
   changes code does this; the build fails when code changed since the last release and "Unreleased" is empty.

Never run `compiled\FreeEDR-Setup.exe` or `FreeEDR-Installer.exe` (install / uninstall) on the owner's PC without explicit approval.
