# FreeEDR - instructions for Claude and other AI agents

**Read [`project_structure.txt`](project_structure.txt) first. It is mandatory and routes you to the docs your task
needs.** In short: after every code change, run `dev_build.cmd` and then, unelevated,
`powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1`. Look into every FAIL and WARN in
`tests\results\last-run.txt` before you say the change is done, and report the `TEST RESULT` line. Never run the
installer or uninstaller on the owner's PC without explicit approval. Rules: [AGENTS.md](AGENTS.md).
