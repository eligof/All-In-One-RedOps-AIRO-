# All In One RedOps (AIRO) Splitter

Build the AIRO toolkit from a single Python script. Generates the full framework (modules, configs, docs, installer/uninstaller) under `airo-redops-v3.2.0/`.

## What’s Included
- Core loader (`airo-core.sh`) with lazy-loading and aliases.
- Modules: network, web, system, privesc (includes `airo getpeas`), cloud, AD, wireless, mobile/IoT, OSINT, automation, utilities.
- Extras for web: `httpxprobe`, `wayback` (gau/waybackurls), `katana`, `nuclei`.
- Mobile helper: `apkdecompile` (apktool/jadx).
- Docs in root and `docs/`.

## Quick Start
```bash
# Install deps (Debian/Ubuntu helper)
chmod +x install_airo_dependencies.sh
./install_airo_dependencies.sh

# Generate package
python airo-splitter.py
cd airo-redops-v3.2.0

# Install
chmod +x install.sh
./install.sh
source ~/.bashrc   # or ~/.zshrc
```

## Runtime Flags
- `--fast` / `--unsafe`: SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000
- `--safe`: re-enable SAFE_MODE
- `--no-delay`, `--delay=<s>`, `--rate-limit=<pps>`

## Web-Focused Commands
- `httpxprobe <target>` – httpx probing (status/title/tech)
- `wayback <domain>` – gau/waybackurls archive URLs
- `katana <url>` – crawler
- `nuclei <url>` – template scans (supports `--templates/--severity/--rate/--output`)
- `dirscan` / `fuzzurl` – SecLists-aware wordlists (`WORDLIST_*` envs), `--threads`, `--extensions`

## Mobile/IoT
- `apkdecompile <apk> [out]` – apktool/jadx outputs
- `apkanalyze`, `ipascan`, `androidscan`, `iotscan`, `firmwareextract`, `bleenum`

## Wordlists & PEAS
- SecLists default path: `$HOME/SecLists` (cloned by helper script).
- `airo getpeas` downloads linPEAS/winPEAS to `$AIRO_HOME/tools/peas`.

## Testing
- Generate and lint shells: `python airo-splitter.py` then `bash -n airo-redops-v3.2.0/modules/*.sh airo-redops-v3.2.0/install.sh airo-redops-v3.2.0/uninstall.sh airo-redops-v3.2.0/airo-core.sh`.

## Contributing / Security
- See `CONTRIBUTING.md` and `SECURITY.md`.

## License
- MIT (see `LICENSE.md`).
