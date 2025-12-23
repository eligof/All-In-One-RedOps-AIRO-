# Security Policy

## Reporting a Vulnerability
- Please email security issues privately to the maintainers rather than opening a public issue.
- Include: affected version/commit, environment, exact command(s) run, and output/error.
- If the issue involves elevated permissions (install/uninstall paths, sudo usage, symlink creation), highlight that clearly.

## Scope
- The installer writes to `$HOME/.airo` and may create a symlink in `/usr/local/bin`; privilege changes in these areas are relevant.
- Generated modules call external security tools; unexpected network activity or unsafe defaults should be reported.

## Response
- We aim to acknowledge reports quickly and provide a timeline for fixes.
- Please avoid disclosure until a fix is released or agreed upon.
