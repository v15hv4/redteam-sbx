#!/bin/bash
# Red Team Tools Installer
# Installs all tools needed for comprehensive security assessments

set -e

echo "=== Red Team Tools Installer ==="
echo ""

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="sudo apt-get install -y"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="sudo pacman -S --noconfirm"
elif command -v yay &> /dev/null; then
    PKG_MANAGER="yay"
    INSTALL_CMD="yay -S --noconfirm"
elif command -v brew &> /dev/null; then
    PKG_MANAGER="brew"
    INSTALL_CMD="brew install"
else
    echo "ERROR: No supported package manager found (apt, pacman, yay, brew)"
    exit 1
fi

echo "Detected package manager: $PKG_MANAGER"
echo ""

# ============================================================
# Core Tools (via package manager)
# ============================================================
echo "=== Installing Core Tools ==="

# Network tools
$INSTALL_CMD nmap curl wget jq dnsutils whois 2>/dev/null || true

# Web testing
$INSTALL_CMD nikto gobuster dirb whatweb 2>/dev/null || true

# SSL/TLS
$INSTALL_CMD sslscan openssl 2>/dev/null || true

# Exploitation
$INSTALL_CMD sqlmap hydra 2>/dev/null || true

# ============================================================
# Go-based tools (ProjectDiscovery suite)
# ============================================================
echo ""
echo "=== Installing ProjectDiscovery Tools ==="

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Go not found. Installing Go..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        sudo apt-get install -y golang-go
    elif [ "$PKG_MANAGER" = "pacman" ] || [ "$PKG_MANAGER" = "yay" ]; then
        $INSTALL_CMD go
    elif [ "$PKG_MANAGER" = "brew" ]; then
        brew install go
    fi
fi

# Set Go paths
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$GOPATH/bin:$PATH"

# Install ProjectDiscovery tools
echo "Installing subfinder (subdomain enumeration)..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true

echo "Installing httpx (HTTP probing)..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true

echo "Installing dnsx (DNS toolkit)..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true

echo "Installing nuclei (vulnerability scanner)..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true

echo "Installing katana (crawler)..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true

echo "Installing naabu (port scanner)..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true

# Other Go tools
echo "Installing waybackurls..."
go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null || true

echo "Installing gau (GetAllUrls)..."
go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true

echo "Installing ffuf (fuzzer)..."
go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null || true

# ============================================================
# Python-based tools
# ============================================================
echo ""
echo "=== Installing Python Tools ==="

# Check pip
if command -v pip3 &> /dev/null; then
    pip3 install --user wafw00f 2>/dev/null || true
    pip3 install --user arjun 2>/dev/null || true
fi

# ============================================================
# Wordlists
# ============================================================
echo ""
echo "=== Installing Wordlists ==="

WORDLIST_DIR="/usr/share/wordlists"
SECLISTS_DIR="/usr/share/seclists"

if [ ! -d "$SECLISTS_DIR" ]; then
    echo "Installing SecLists..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        sudo apt-get install -y seclists 2>/dev/null || \
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    elif [ "$PKG_MANAGER" = "pacman" ] || [ "$PKG_MANAGER" = "yay" ]; then
        $INSTALL_CMD seclists 2>/dev/null || \
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
    else
        sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || true
    fi
fi

# ============================================================
# Nuclei Templates
# ============================================================
echo ""
echo "=== Updating Nuclei Templates ==="
if command -v nuclei &> /dev/null; then
    nuclei -update-templates 2>/dev/null || true
fi

# ============================================================
# Verification
# ============================================================
echo ""
echo "=== Tool Verification ==="
echo ""

tools=(
    "nmap:Port scanner"
    "dig:DNS lookup"
    "curl:HTTP client"
    "jq:JSON processor"
    "whois:WHOIS lookup"
    "subfinder:Subdomain enumeration"
    "httpx:HTTP prober"
    "dnsx:DNS toolkit"
    "nuclei:Vulnerability scanner"
    "nikto:Web scanner"
    "gobuster:Directory brute force"
    "sqlmap:SQL injection"
    "hydra:Brute force"
    "whatweb:Web fingerprinting"
    "sslscan:SSL/TLS scanner"
    "ffuf:Web fuzzer"
    "katana:Web crawler"
    "waybackurls:Wayback Machine URLs"
)

echo "| Tool | Status | Description |"
echo "|------|--------|-------------|"

for item in "${tools[@]}"; do
    tool="${item%%:*}"
    desc="${item#*:}"
    if command -v "$tool" &> /dev/null; then
        echo "| $tool | ✓ Installed | $desc |"
    else
        echo "| $tool | ✗ Missing | $desc |"
    fi
done

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Add Go bin to PATH if not already:"
echo "  export PATH=\"\$HOME/go/bin:\$PATH\""
echo ""
echo "Run /redteam <domain> to start an assessment."
