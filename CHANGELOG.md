# Changelog

## 3.3.3 - 2025-12-28
- Capture dnscan output reliably and add sqlmap non-interactive defaults.
- Add draft findings to reportgen based on collected artifacts.

## 3.3.2 - 2025-12-28
- Ensure sudo runs use the invoking user's XDG paths for module loading.
- Prompt for scan impact once per session (per shell).
- Ship dependency installer into AIRO_HOME and auto-clone SecLists when missing.
- Improve portscan/udpscan output handling and use unprivileged TCP scans without sudo.
- Reportgen now links the latest runlist log when available.

## 3.3.1 - 2025-12-28
- Added VERSION file as the single source of truth for package versioning.
- Runlist now writes full output + summary to a log file by default.
- Auto-install missing tools by default and enforce required Go tool installs.
- Reduced banner noise (once per session) and added NO_PROMPT/QUIET config support.
- Improved web workflow robustness (301 normalization, better sql/xss checks, report linkage).

## 3.3.0 - 2025-12-24
- Modular splitter generates XDG‑aware package layout.
- Runtime flags for safety, dry‑run, debug, proxy/Tor, jitter, and JSON logs.
- Improved installer/uninstaller with manifest and rollback.
- Added documentation set, packaging artifacts, and GitHub Actions CI.
