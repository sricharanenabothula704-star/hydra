#!/usr/bin/env bash
# ==============================================================
# Best-effort installer for the recon toolchain.
# Skips anything already installed. Run as normal user;
# sudo used only for apt where available.
# ==============================================================
set -uo pipefail

have() { command -v "$1" >/dev/null 2>&1; }

echo "[*] Installing AI Bug Bounty System toolchain..."

# --- system packages -------------------------------------------
if have apt-get; then
  SUDO=""; [ "$(id -u)" -ne 0 ] && have sudo && SUDO="sudo"
  $SUDO apt-get update -qq
  for p in nmap jq sqlmap python3-pip git curl; do
    have "$p" || $SUDO apt-get install -y -qq "$p" || echo "[!] apt: $p failed"
  done
  have wafw00f || pip3 install --quiet wafw00f || true
fi

# --- go tools ---------------------------------------------------
if ! have go; then
  echo "[!] Go not found — install from https://go.dev/dl/ and re-run."
else
  export GOBIN="${GOBIN:-$HOME/go/bin}"
  mkdir -p "$GOBIN"
  install_go() { # name importpath
    if have "$1"; then echo "[✓] $1 already installed"; return; fi
    echo "[*] Installing $1..."
    go install -v "$2@latest" 2>/dev/null \
      || echo "[!] $1 install failed (check $2)"
  }
  install_go subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder
  install_go assetfinder  github.com/tomnomnom/assetfinder
  install_go httpx        github.com/projectdiscovery/httpx/cmd/httpx
  install_go naabu        github.com/projectdiscovery/naabu/v2/cmd/naabu
  install_go nuclei       github.com/projectdiscovery/nuclei/v2/cmd/nuclei
  install_go dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx
  install_go chaos        github.com/projectdiscovery/chaos-client/cmd/chaos
  install_go interactsh   github.com/projectdiscovery/interactsh/cmd/interactsh-client
  install_go ffuf         github.com/ffuf/ffuf/v2
  install_go dalfox       github.com/hahwul/dalfox/v2
  install_go gau          github.com/lc/gau/v2/cmd/gau
  install_go waybackurls  github.com/tomnomnom/waybackurls
  install_go gf           github.com/tomnomnom/gf
  install_go qsreplace    github.com/tomnomnom/qsreplace
  install_go uro          github.com/s0md3v/uro
  install_go gospider     github.com/jaeles-project/gospider
fi

# --- nuclei templates -------------------------------------------
if have nuclei; then
  echo "[*] Updating nuclei templates..."
  nuclei -update-templates >/dev/null 2>&1 || true
fi

# --- PATH hint ---------------------------------------------------
case ":$PATH:" in
  *":$HOME/go/bin:"*) ;;
  *) echo "[!] Add Go binaries to PATH:"
     echo '    echo "export PATH=\$HOME/go/bin:\$PATH" >> ~/.bashrc && source ~/.bashrc' ;;
esac

echo ""
echo "[✓] Done. Verify with:"
echo "    for t in subfinder httpx naabu nuclei ffuf gau waybackurls uro gf dalfox nmap jq; do command -v \$t >/dev/null && echo \"[✓] \$t\" || echo \"[!] \$t missing\"; done"
