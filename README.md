# All In One RedOps (AIRO) Splitter

Generate the AIRO toolkit from one Python script. AIRO exists to give red/purple teams a fast, modular, “drop-in” toolkit: build once, install anywhere, and get 150+ tasks (recon → exploitation → reporting) with sensible defaults and safety controls.

## Why use it?
- One command builds a full framework: modules, configs, docs, installer/uninstaller.
- Modular and lazy-loaded: keeps shells light; only loads what you call.
- Web/mobile ready: httpx/katana/nuclei/wayback for web; apktool/jadx helpers for mobile.
- Safety first, speed when you want: SAFE_MODE prompts by default; `--fast` removes delays/rate limits.
- XDG-friendly: config under `$XDG_CONFIG_HOME/airo`, data under `$XDG_DATA_HOME/airo`.

## Quick Start
```bash
# Install deps (Debian/Ubuntu helper)
chmod +x install_airo_dependencies.sh
./install_airo_dependencies.sh

# Generate the package
python airo-splitter.py
cd airo-redops-v3.2.0

# Install
chmod +x install.sh
./install.sh
source ~/.bashrc   # or ~/.zshrc
```

## Usage (common commands)
```bash
airo httpxprobe https://target.com                # tech + status + title
airo wayback target.com --output urls.txt         # URLs from gau/waybackurls
airo katana https://target.com -o crawl.txt       # crawl endpoints
airo nuclei https://target.com --severity=high    # template scan
airo dirscan https://target.com --threads 50      # directory bruteforce (SecLists-aware)
airo fuzzurl https://target.com --wordlist raft-medium
airo portscan 10.0.0.5 --top 100 --output scan.txt
airo --fast vulnscan target.com --nmap-opts "-sV"
airo apkdecompile app.apk ./out_apk               # mobile decompilation
airo getpeas                                       # fetch linPEAS/winPEAS
airo reportgen                                     # scaffold a report template
```

## Runtime Flags (per run)
- `--fast` / `--unsafe`: SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000
- `--safe`: re-enable SAFE_MODE
- `--no-delay`, `--delay=<s>`, `--rate-limit=<pps>`
- `--dry-run`: show what would run without executing
- `--verbose`: extra detail for `--dry-run`
- `--debug`: enable bash tracing for commands
- `--proxy <url>`: route HTTP tools via proxy
- `--tor`: use Tor SOCKS proxy at `127.0.0.1:9050`
- `--user-agent <ua>` / `--ua <ua>`: set User‑Agent
- `--jitter <s>`: add random delay jitter
- `--json-log`: log commands to JSON

## Web Toolkit (highlights)
- `httpxprobe` – httpx probing (status/title/tech)
- `wayback` – gau/waybackurls archive URLs
- `katana` – fast crawler
- `nuclei` – template scans (`--templates/--severity/--rate/--output`)
- `dirscan` / `fuzzurl` – SecLists-aware wordlists (`WORDLIST_*`), `--threads`, `--extensions`

## Mobile / IoT
- `apkdecompile <apk> [out]` – apktool/jadx outputs
- `apkanalyze`, `ipascan`, `androidscan`, `iotscan`, `firmwareextract`, `bleenum`

## Automation & Reporting
- `reconall <domain> [--out --target --nmap-opts]`
- `vulnscan <target> [--out --nmap-opts --nikto-opts]`
- `reportgen` – creates a report template scaffold
- `findings` / `evidence` – simple checklists/placeholders

## Wordlists & PEAS
- SecLists expected at `$HOME/SecLists` (cloned by helper).
- `airo getpeas` downloads linPEAS/winPEAS to `$AIRO_HOME/tools/peas`.
- Env overrides: `WORDLIST_BASE`, `WORDLIST_DIRSCAN`, `WORDLIST_FUZZURL`.

## Config Paths (XDG)
- Config: `$XDG_CONFIG_HOME/airo` (fallback `~/.config/airo`)
- Data: `$XDG_DATA_HOME/airo` (fallback `~/.local/share/airo`)
- Cache: `$XDG_CACHE_HOME/airo` (fallback `~/.cache/airo`)
- Logs: `$XDG_CACHE_HOME/airo/logs/airo.log`
- JSON log: `$XDG_CACHE_HOME/airo/logs/commands.jsonl`

## Testing
Generate and lint shells:
```bash
python airo-splitter.py
bash -n airo-redops-v3.2.0/modules/*.sh \
       airo-redops-v3.2.0/install.sh \
       airo-redops-v3.2.0/uninstall.sh \
       airo-redops-v3.2.0/airo-core.sh
```

Run tests:
```bash
python -m pytest -q
```

## Contributing / Security / License
- Contributing: `CONTRIBUTING.md`
- Security: `SECURITY.md`
- License: MIT (`LICENSE.md`)
