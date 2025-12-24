#!/usr/bin/env bash
set -euo pipefail

# Fast dependency installer for AIRO on Debian/Ubuntu-like systems.
# Installs common tools, wordlists (SecLists), and Python deps.

APT_PKGS=(
  nmap whois nikto gobuster dirb ffuf sqlmap wpscan joomscan sslscan testssl.sh whatweb subfinder grc
  awscli docker.io kubectl enum4linux ldap-utils aircrack-ng bluetooth bluez bettercap
  apktool zipalign adb gatttool exiftool xxd file python3-pip git golang-go jadx
)

echo "[*] Updating package index..."
sudo apt update

echo "[*] Installing packages: ${APT_PKGS[*]}"
sudo apt install -y "${APT_PKGS[@]}"

echo "[*] Installing Python deps (user scope)..."
pip3 install --user haveibeenpwned

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
else
  echo "[-] Go toolchain not found; install golang-go and rerun to fetch httpx/katana/nuclei/gau/waybackurls."
fi

echo "[*] Done. Optional: run 'airo getpeas' after generating the package to fetch linPEAS/winPEAS."
