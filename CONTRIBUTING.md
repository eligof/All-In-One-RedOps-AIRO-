# Contributing to AIRO Splitter

Thanks for your interest in improving the AIRO splitter! Please follow these guidelines to keep changes smooth and reviewable.

## Workflow
- Fork or create a branch off `main`.
- Keep changes scoped; prefer focused PRs over large, mixed ones.
- Run the generator: `python airo-splitter.py` and validate that generated scripts pass `bash -n airo-redops-v3.2.0/modules/*.sh`.
- Document new flags or commands in the README/DOCS section within `airo-splitter.py`.

## Coding Style
- Python: prefer clear, explicit code; avoid unnecessary dependencies.
- Bash (generated): keep POSIX-ish where possible; guard external tool calls with `command -v`.
- Default to ASCII; avoid introducing non-ASCII unless needed.
- Add brief comments only when behavior isn’t obvious.

## Testing
- Lint shell scripts: `bash -n airo-redops-v3.2.0/modules/*.sh airo-redops-v3.2.0/install.sh airo-redops-v3.2.0/uninstall.sh airo-redops-v3.2.0/airo-core.sh`.
- For new commands, provide a minimal usage example or dry-run path; avoid hitting external targets in tests.

## Pull Requests
- Describe what changed and why; include any new flags/commands and dependencies.
- Note any manual steps (e.g., new external tools to install).
- Keep commits clean and logically grouped.

## Security / Sensitive Code
- Don’t commit secrets or keys.
- Flag any changes that affect install paths, permissions, or network calls.
