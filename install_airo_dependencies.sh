#!/usr/bin/env bash
set -euo pipefail

# Dependency installer for AIRO on Debian/Ubuntu-like systems.
# Installs common tools, wordlists (SecLists), Python deps, and provides fallbacks
# when packages are not available in the default repositories.

APT_REQUIRED=(
  nmap whois nikto gobuster dirb ffuf sqlmap sslscan testssl.sh whatweb grc
  docker.io ldap-utils aircrack-ng bluetooth bluez bettercap
  apktool zipalign adb exiftool xxd file python3-pip git golang-go perl
)

APT_OPTIONAL=(
  wpscan joomscan subfinder awscli kubectl enum4linux gatttool jadx
)

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

install_available_apt_pkgs() {
  local pkgs=("$@")
  local available=()
  local missing=()
  for pkg in "${pkgs[@]}"; do
    if apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}' | grep -vq "(none)"; then
      available+=("$pkg")
    else
      missing+=("$pkg")
    fi
  done
  if ((${#available[@]})); then
    echo "[*] Installing APT packages: ${available[*]}"
    sudo apt install -y "${available[@]}"
  fi
  if ((${#missing[@]})); then
    echo "[!] Missing from APT repos: ${missing[*]}"
  fi
}

echo "[*] Updating package index..."
sudo apt update

install_available_apt_pkgs "${APT_REQUIRED[@]}"
install_available_apt_pkgs "${APT_OPTIONAL[@]}"

echo "[*] Installing Python deps (user scope)..."
pip3 install --user haveibeenpwned || true

if [[ ! -d "$HOME/SecLists" ]]; then
  echo "[*] Cloning SecLists to $HOME/SecLists"
  git clone https://github.com/danielmiessler/SecLists.git "$HOME/SecLists"
else
  echo "[*] SecLists already present at $HOME/SecLists"
fi

echo "[*] Installing Go-based tools (httpx, katana, nuclei, gau, waybackurls)..."
if command -v go >/dev/null 2>&1; then
  export GO111MODULE=on
  # Ensure GOPATH/bin is on PATH for this session
  export PATH="$(go env GOPATH)/bin:${PATH}"
  go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.0
  go install github.com/projectdiscovery/katana/cmd/katana@v1.0.5
  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@v3.2.0
  go install github.com/lc/gau/v2/cmd/gau@v2.1.2
  go install github.com/tomnomnom/waybackurls@v0.1.0
  if ! command_exists subfinder; then
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  fi
else
  echo "[-] Go toolchain not found; install golang-go and rerun to fetch httpx/katana/nuclei/gau/waybackurls."
fi

if ! command_exists aws; then
  echo "[*] awscli not found; attempting pip install (user scope)"
  pip3 install --user awscli || true
  if ! command_exists aws; then
    echo "[!] awscli still missing. Ensure ~/.local/bin is on PATH:"
    echo "    export PATH=\"$HOME/.local/bin:\$PATH\""
  fi
fi

if ! command_exists kubectl; then
  if apt-cache show kubernetes-client >/dev/null 2>&1; then
    echo "[*] Installing kubectl via kubernetes-client"
    sudo apt install -y kubernetes-client || true
  else
    echo "[!] kubectl not available in default repos. Install from https://kubernetes.io/docs/tasks/tools/."
  fi
fi

if ! command_exists wpscan; then
  echo "[*] wpscan not found; attempting Ruby install"
  if ! command_exists gem; then
    sudo apt install -y ruby-full || true
  fi
  if command_exists gem; then
    sudo gem install wpscan --no-document || true
  fi
fi

if ! command_exists joomscan; then
  echo "[*] joomscan not found; attempting git install"
  if command_exists git; then
    if command_exists sudo; then
      sudo mkdir -p /opt/joomscan
      if [[ ! -d /opt/joomscan/.git ]]; then
        sudo git clone https://github.com/rezasp/joomscan.git /opt/joomscan || true
      else
        sudo git -C /opt/joomscan pull || true
      fi
      sudo ln -sf /opt/joomscan/joomscan.pl /usr/local/bin/joomscan || true
    else
      mkdir -p "$HOME/.local/joomscan"
      if [[ ! -d "$HOME/.local/joomscan/.git" ]]; then
        git clone https://github.com/rezasp/joomscan.git "$HOME/.local/joomscan" || true
      else
        git -C "$HOME/.local/joomscan" pull || true
      fi
      mkdir -p "$HOME/.local/bin"
      ln -sf "$HOME/.local/joomscan/joomscan.pl" "$HOME/.local/bin/joomscan" || true
    fi
  fi
fi

if ! command_exists jadx; then
  echo "[!] jadx not found in PATH. Install from https://github.com/skylot/jadx/releases or your package manager."
fi

if ! command_exists gatttool; then
  if apt-cache show bluez-tools >/dev/null 2>&1; then
    sudo apt install -y bluez-tools || true
  fi
  if ! command_exists gatttool; then
    echo "[!] gatttool not available; BLE commands may be limited on newer distros."
  fi
fi

echo "[*] Done. Optional: run 'airo getpeas' after generating the package to fetch linPEAS/winPEAS."
