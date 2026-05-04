#!/usr/bin/env bash
# threat_intel_scan.sh — Pre-audit threat intelligence scanner (16-phase)
#
# Usage:
#   bash threat_intel_scan.sh <project_root>
#
# Exit codes:
#   0  = CLEAN (LOW/INFO only)
#   10 = MEDIUM findings (warn, ask user)
#   20 = HIGH findings (block)
#   3  = Scan timeout
#   1  = Script error

set -euo pipefail
export LC_ALL=C

for cmd in find grep sed; do
  command -v "$cmd" &>/dev/null || { echo "❌ Required tool not found: $cmd"; exit 1; }
done

trap 'echo "❌ Scan failed with unexpected error (exit code $?)"; exit 1' ERR

SCAN_TIMEOUT=300
SCAN_START=$(date +%s)
check_timeout() {
  local now
  now=$(date +%s)
  if [ $((now - SCAN_START)) -gt $SCAN_TIMEOUT ]; then
    echo "⚠️  Scan timeout (${SCAN_TIMEOUT}s) — aborting."
    exit 3
  fi
}

TARGET="${1:-.}"
[ -d "$TARGET" ] || { echo "❌ Directory not found: $TARGET"; exit 1; }

HIGH_COUNT=0; MEDIUM_COUNT=0; LOW_COUNT=0; INFO_COUNT=0
HIGH_FINDINGS=(); MEDIUM_FINDINGS=(); LOW_FINDINGS=(); INFO_FINDINGS=()

# Phase pass/fail tracking (f=findings, p=pass)
P1=p;P2=p;P3=p;P4=p;P5=p;P6=p;P7=p;P8=p
P9=p;P10=p;P11=p;P12=p;P13=p;P14=p;P15=p;P16=p

add_finding() {
  local sev="$1" cat="$2" det="$3"
  local entry="[$sev] $cat: $det"
  case "$sev" in
    HIGH)
      HIGH_FINDINGS+=("$entry"); HIGH_COUNT=$((HIGH_COUNT+1))
      case "$CURRENT_PHASE" in
        1) P1=f;; 2) P2=f;; 3) P3=f;; 4) P4=f;; 5) P5=f;; 6) P6=f;;
        7) P7=f;; 8) P8=f;; 9) P9=f;; 10) P10=f;; 11) P11=f;; 12) P12=f;;
        13) P13=f;; 14) P14=f;; 15) P15=f;; 16) P16=f;;
      esac ;;
    MEDIUM)
      MEDIUM_FINDINGS+=("$entry"); MEDIUM_COUNT=$((MEDIUM_COUNT+1))
      case "$CURRENT_PHASE" in
        1) P1=f;; 2) P2=f;; 3) P3=f;; 4) P4=f;; 5) P5=f;; 6) P6=f;;
        7) P7=f;; 8) P8=f;; 9) P9=f;; 10) P10=f;; 11) P11=f;; 12) P12=f;;
        13) P13=f;; 14) P14=f;; 15) P15=f;; 16) P16=f;;
      esac ;;
    LOW)    LOW_FINDINGS+=("$entry");    LOW_COUNT=$((LOW_COUNT+1))    ;;
    INFO)   INFO_FINDINGS+=("$entry");   INFO_COUNT=$((INFO_COUNT+1))  ;;
  esac
}

phase_status() {
  local v="$1"
  [ "$v" = "p" ] && echo "pass" || echo "FINDINGS"
}

CURRENT_PHASE=0

echo "🐝 Scoping Bee — Threat Intelligence Scan"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: $TARGET"
echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ════════════════════════════════════════════════════════════════
# PHASE 1: CODE EXECUTION & PERSISTENCE
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=1
check_timeout
echo "🔍 Phase 1:  Code Execution & Persistence..."

# 1.1 Auto-execution lifecycle hooks
if [ -f "$TARGET/package.json" ]; then
  suspect=$(grep -E '"(postinstall|preinstall|prepare|prepublish|prepublishOnly|prepack|postpack)"\s*:' \
    "$TARGET/package.json" 2>/dev/null || true)
  [ -n "$suspect" ] && add_finding "HIGH" "Auto-exec lifecycle" \
    "package.json has auto-run hook(s): $(echo "$suspect" | head -1 | tr -d ' ')"
fi

# setup.py cmdclass overrides
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(cmdclass|install_requires)\s*=.*\{|class\s+\w+\s*\(\s*(install|develop|build)\s*\)' \
    "$f" 2>/dev/null | head -3 || true)
  [ -n "$hit" ] && add_finding "HIGH" "setup.py exec hook" \
    "$rel: setup.py overrides install/develop command class — runs on pip install"
done < <(find "$TARGET" -name "setup.py" -not -path "*/node_modules/*" \
  -not -path "*/target/*" 2>/dev/null)

# Makefile auto-targets with network/exec
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '^\s*(curl |wget |bash |sh |python |node |exec )' "$f" 2>/dev/null | head -3 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Makefile exec" "$rel: Makefile runs network/shell commands"
done < <(find "$TARGET" -name "Makefile" -o -name "makefile" 2>/dev/null | \
  grep -v "node_modules" | grep -v "target/" || true)

# build.rs with network or process execution (Rust)
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(Command::new|std::process|reqwest|ureq|std::net|TcpStream)' \
    "$f" 2>/dev/null | head -3 || true)
  [ -n "$hit" ] && add_finding "HIGH" "build.rs exec/network" \
    "$rel: Rust build script spawns processes or makes network calls"
done < <(find "$TARGET" -name "build.rs" -not -path "*/target/*" 2>/dev/null)

# GitHub Actions: curl|bash, encoded payloads, secret exfiltration
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  curl_bash=$(grep -nE '(curl|wget).*\|\s*(ba)?sh' "$f" 2>/dev/null | head -2 || true)
  [ -n "$curl_bash" ] && add_finding "HIGH" "GitHub Actions curl|bash" \
    "$rel: workflow pipes curl to shell"
  encoded=$(grep -nE 'base64\s*(-d|--decode)|echo.*\|\s*(ba)?sh' "$f" 2>/dev/null | head -2 || true)
  [ -n "$encoded" ] && add_finding "HIGH" "GitHub Actions encoded payload" \
    "$rel: workflow executes base64-decoded payload"
  secret_exfil=$(grep -nE '(curl|wget).*secrets\.|toJSON\(secrets\)' "$f" 2>/dev/null | head -2 || true)
  [ -n "$secret_exfil" ] && add_finding "HIGH" "GitHub Actions secret exfil" \
    "$rel: workflow may exfiltrate repository secrets"
done < <(find "$TARGET/.github/workflows" -name "*.yml" -o -name "*.yaml" 2>/dev/null || true)

# Docker entrypoints with network/exec commands
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(ENTRYPOINT|CMD)\s.*\[(.*curl|wget|bash|sh|python|nc\b)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Docker exec entrypoint" \
    "$rel: ENTRYPOINT/CMD includes network or shell commands"
done < <(find "$TARGET" -name "Dockerfile*" -not -path "*/node_modules/*" 2>/dev/null)

# 1.2 Process spawning in JS/TS/Python source
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '\b(eval\s*\(|execSync\s*\(|spawnSync\s*\(|child_process|new\s+Function\s*\()' \
    "$f" 2>/dev/null | grep -v "node_modules" | head -3 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Dynamic code execution" \
    "$rel: eval/execSync/spawn/new Function patterns"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \
  -o -name "*.jsx" -o -name "*.tsx" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/dist/*" \
  -not -path "*/build/*" -not -path "*/target/*" 2>/dev/null)

# 1.3 Dynamic code loading: require() with variable path
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE 'require\s*\(\s*[^"'"'"']|\bimportlib\.import_module\s*\(|\b__import__\s*\(' \
    "$f" 2>/dev/null | head -3 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Dynamic import" \
    "$rel: dynamic require()/import_module() with variable path"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.py" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# Compiled binaries / shared objects
while IFS= read -r f; do
  add_finding "HIGH" "Suspicious binary" \
    "Compiled binary found: $(echo "$f" | sed "s|$TARGET/||")"
done < <(find "$TARGET" \( -name "*.exe" -o -name "*.dll" -o -name "*.so" \
  -o -name "*.dylib" -o -name "*.elf" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# Symlinks pointing outside repo
while IFS= read -r f; do
  link_target=$(readlink "$f" 2>/dev/null || true)
  if [ -n "$link_target" ]; then
    abs_link=$(cd "$(dirname "$f")" && realpath "$link_target" 2>/dev/null || echo "$link_target")
    abs_repo=$(realpath "$TARGET" 2>/dev/null || echo "$TARGET")
    case "$abs_link" in
      "$abs_repo"*) ;;
      *) add_finding "HIGH" "External symlink" \
           "$(echo "$f" | sed "s|$TARGET/||") → $link_target (outside repo)" ;;
    esac
  fi
done < <(find "$TARGET" -type l -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# Forge FFI
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE 'vm\.ffi\(' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Forge FFI" \
    "$rel: vm.ffi() calls can execute arbitrary shell commands"
done < <(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null)

# Hex shellcode
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(\\x[0-9a-fA-F]{2}){10,}' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Hex shellcode" \
    "$rel: hex-encoded byte sequence (possible shellcode)"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 2: NETWORK EXFILTRATION & C2
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=2
check_timeout
echo "🌐 Phase 2:  Network Exfiltration & C2..."

# 2.1 HTTP outbound in non-config source files
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(curl |wget |fetch\(|http\.get|https\.get|axios\.|XMLHttpRequest|sendBeacon|requests\.(get|post)|urllib\.(request|urlopen))' \
    "$f" 2>/dev/null | head -3 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "HTTP outbound" \
    "$rel: outbound network call detected"
done < <(find "$TARGET" \( -name "*.sh" -o -name "*.js" -o -name "*.ts" -o -name "*.py" \
  -o -name "*.mjs" -o -name "*.cjs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" \
  -not -path "*/test/*" -not -path "*/tests/*" \
  -not -name "hardhat.config.*" -not -name "*.config.*" 2>/dev/null)

# 2.2 DNS-based exfiltration
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(dns\.resolve|dns\.lookup|nslookup|dig\s).*\$|base64.*dns|dns.*base64' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "DNS exfiltration" \
    "$rel: DNS queries with encoded data — possible covert channel"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 2.4 Email / messaging exfiltration
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(nodemailer|sendgrid|mailgun|smtp\.|SMTP|twilio|sns\.publish|api\.telegram\.org|discord.*webhook|slack.*webhook)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Messaging exfiltration" \
    "$rel: email/messaging API — potential data exfiltration channel"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 2.5 Cloud storage exfiltration
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(s3\.putObject|\.upload\s*\(|storage\.bucket|uploadBlockBlob|firebase.*\.set\s*\(|ipfs\.add|pastebin\.com|gist\.github)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Cloud storage exfil" \
    "$rel: uploads data to cloud storage or paste service"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 2.3 WebSocket (C2 channel)
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(new\s+WebSocket\s*\(|wss?://[^'"'"'"]+\.)' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "LOW" "WebSocket connection" \
    "$rel: WebSocket — verify it is not a C2 channel"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 3: OBFUSCATION & ENCODING
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=3
check_timeout
echo "🔒 Phase 3:  Obfuscation & Encoding..."

# 3.1 Large base64 strings
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '[A-Za-z0-9+/]{100,}={0,2}' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Base64 payload" \
    "$rel: large base64-encoded string (>100 chars)"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \
  -o -name "*.rs" -o -name "*.html" -o -name "*.mjs" -o -name "*.cjs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" \
  -not -path "*/typechain-types/*" -not -path "*/artifacts/*" -not -path "*/out/*" 2>/dev/null)

# 3.2 Hex encoding (Buffer.from hex)
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE "(Buffer\.from\s*\([^,]+,\s*['\"]hex['\"]|bytes\.fromhex\s*\(|hex::decode)" \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Hex decoding" \
    "$rel: hex-encoded data decoded at runtime"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.rs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 3.3 String obfuscation
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(String\.fromCharCode\s*\([0-9,\s]{20,}\)|String\.fromCodePoint\s*\(|\.split\s*\(\s*['"'"'"'"'"']\s*\)\.reverse\s*\(\s*\)\.join)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "String obfuscation" \
    "$rel: fromCharCode/reverse-join — classic JS obfuscation"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 3.4 JavaScript obfuscator patterns (_0x, JSFuck, eval(function(p,a,c,k)
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  obf=$(grep -nE '(_0x[a-f0-9]{4,}|\[!\[\]\+\[\]|\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k|window\["ev"\+"al"\])' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$obf" ] && add_finding "HIGH" "JS obfuscation" \
    "$rel: obfuscated JS (_0x / JSFuck / packer)"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/dist/*" -not -path "*/build/*" \
  -not -path "*/target/*" 2>/dev/null)

# 3.5 Crypto mining
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nEi '(coinhive|cryptonight|monero|stratum\+tcp|hashrate|CryptoLoot|deepMiner|CoinImp|getHashesPerSecond)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Crypto mining" \
    "$rel: cryptocurrency mining patterns"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.html" -o -name "*.wasm" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 3.6 Unicode abuse: RTL override, zero-width chars
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nP '[\x{200b}\x{200c}\x{200d}\x{feff}\x{202e}]' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Unicode abuse" \
    "$rel: zero-width or RTL-override characters — filename/display spoofing"
done < <(find "$TARGET" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" \
  -not -path "*/target/*" 2>/dev/null) 2>/dev/null || true

# 3.7 Serialization: pickle.loads, yaml.load unsafe, PHP unserialize
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(pickle\.(loads|load)\s*\(|yaml\.load\s*\([^)]*\)(?!.*SafeLoader)|Marshal\.load\s*\(|unserialize\s*\()' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Unsafe deserialization" \
    "$rel: pickle/yaml.load/unserialize — arbitrary code execution on untrusted data"
done < <(find "$TARGET" \( -name "*.py" -o -name "*.rb" -o -name "*.php" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 4: CREDENTIAL & SECRET THEFT
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=4
check_timeout
echo "🔑 Phase 4:  Credential & Secret Theft..."

# 4.1 Hardcoded secrets (API keys, private keys, JWTs)
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  # Skip test/mock/fixture files
  case "$rel" in *test*|*mock*|*fixture*|*example*|*sample*) continue ;; esac
  # Ethereum private key (64 hex chars)
  eth_key=$(grep -nE '0x[a-fA-F0-9]{64}' "$f" 2>/dev/null | \
    grep -vE '(bytes32|uint256|hash|root|merkle|ZERO|EMPTY)' | head -2 || true)
  [ -n "$eth_key" ] && add_finding "HIGH" "Hardcoded private key" \
    "$rel: 64-byte hex value — possible Ethereum private key"
  # API key patterns
  api_key=$(grep -nE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20}|xox[bpsa]-[0-9]{10,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35})' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$api_key" ] && add_finding "HIGH" "Hardcoded API key" \
    "$rel: known API key format (AWS/GitHub/GitLab/Slack/OpenAI/Google)"
  # JWT
  jwt=$(grep -nE 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$jwt" ] && add_finding "HIGH" "Hardcoded JWT" \
    "$rel: JWT token hardcoded in source"
  # BIP39 mnemonic-length patterns (12 or 24 words)
  mnemonic=$(grep -nE '\b([a-z]{3,8}\s+){11}[a-z]{3,8}\b' "$f" 2>/dev/null | head -1 || true)
  [ -n "$mnemonic" ] && add_finding "HIGH" "Possible mnemonic" \
    "$rel: 12-word sequence — possible BIP39 seed phrase"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \
  -o -name "*.env" -o -name "*.json" -o -name "*.toml" -o -name "*.yaml" -o -name "*.yml" \
  -o -name "*.rs" -o -name "*.sol" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" \
  -not -path "*/.git/*" -not -name "*.lock" 2>/dev/null)

# Keypair/wallet files in repo
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  add_finding "HIGH" "Wallet/keypair file" \
    "$rel: wallet or keypair file present in repository"
done < <(find "$TARGET" -type f \
  \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \
  -o -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \) \
  -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)

# 4.2 Browser storage theft
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nEi '(document\.cookie|localStorage\.getItem|sessionStorage\.getItem|indexedDB|navigator\.credentials)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Storage access" \
    "$rel: reads cookies/localStorage/sessionStorage — verify no exfiltration"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.html" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 4.3 Clipboard hijacking
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nEi '(navigator\.clipboard\.(write|read)|document\.execCommand\(['"'"'"'"'"']copy|clipboardData\.setData|oncopy|oncut)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Clipboard access" \
    "$rel: clipboard write/read — potential address-swap attack"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 4.4 Keylogging
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nEi '(addEventListener\(['"'"'"'"'"'](keydown|keyup|keypress|input)['"'"'"'"'"']|onkeydown|onkeyup|onkeypress)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "LOW" "Keyboard listener" \
    "$rel: keyboard event listeners — verify not keylogging"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 4.5 Screen/media capture
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nEi '(getUserMedia|getDisplayMedia|MediaRecorder|html2canvas|dom-to-image)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Screen/media capture" \
    "$rel: screen recording or camera access API"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 4.6 Environment variable harvesting
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(process\.env\b(?!\.(NODE_ENV|PATH|HOME|USER|PWD|SHELL))|\bos\.environ\b|std::env::vars\s*\(\s*\))' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Env var access" \
    "$rel: accesses process environment — verify no credential harvesting"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.rs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 5: FILESYSTEM & SYSTEM ACCESS
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=5
check_timeout
echo "📁 Phase 5:  Filesystem & System Access..."

# 5.1 Reads of sensitive host paths
SENSITIVE_PATHS='(~\/\.ssh\/|~\/\.aws\/|~\/\.kube\/|~\/\.gnupg\/|\/etc\/passwd|\/etc\/shadow|~\/\.ethereum\/|~\/\.config\/solana\/|~\/\.netrc|~\/\.gitconfig)'
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE "$SENSITIVE_PATHS" "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Sensitive path access" \
    "$rel: reads sensitive host paths (SSH/AWS/kubeconfig/wallet)"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \
  -o -name "*.rs" -o -name "*.go" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 5.2 Path traversal patterns
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(\.\.[/\\]){2,}|%2e%2e[/\\]|%252e%252e' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Path traversal" \
    "$rel: path traversal pattern (../../)"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.php" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 5.2 /proc/self/ access
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '/proc/(self|[0-9]+)/' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "HIGH" "Proc filesystem access" \
    "$rel: reads /proc/ — process memory/env harvesting"
done < <(find "$TARGET" \( -name "*.py" -o -name "*.sh" -o -name "*.js" -o -name "*.go" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 5.3 File permission manipulation
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(chmod\s+[+]?x|chmod\s+777|chmod\s+[0-9]*[67][0-9][0-9]|setuid|setgid)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Permission manipulation" \
    "$rel: chmod +x / 777 / setuid — escalation risk"
done < <(find "$TARGET" \( -name "*.sh" -o -name "*.py" -o -name "Makefile" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 5.5 Sensitive files in repository
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  case "$(basename "$f")" in
    *.env.example|*.env.sample) continue ;;
  esac
  add_finding "LOW" ".env file" "$rel — may contain secrets"
done < <(find "$TARGET" -maxdepth 4 -name ".env" -o -name ".env.*" 2>/dev/null | \
  grep -v "node_modules" | grep -v ".env.example" | grep -v ".env.sample" || true)

# Keypair/wallet JSON references in scripts
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(keypair|wallet|key)\.(json|key|pem)' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Keypair reference" \
    "$rel: references wallet/keypair file"
done < <(find "$TARGET" \( -name "*.sh" -o -name "*.ts" -o -name "*.js" -o -name "Anchor.toml" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# Large binary files (>1MB, unexpected in source repos)
while IFS= read -r f; do
  size=$(wc -c < "$f" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$size" -gt 1048576 ]; then
    sz=$(echo "scale=1; $size / 1048576" | bc 2>/dev/null || echo "?")
    add_finding "LOW" "Large binary file" \
      "$(echo "$f" | sed "s|$TARGET/||") (${sz}MB)"
  fi
done < <(find "$TARGET" -type f \
  -not -path "*/node_modules/*" -not -path "*/.git/*" \
  -not -path "*/target/*" -not -path "*/lib/*" \
  -not -name "*.sol" -not -name "*.rs" -not -name "*.ts" -not -name "*.js" \
  -not -name "*.json" -not -name "*.toml" -not -name "*.md" \
  -not -name "*.txt" -not -name "*.yaml" -not -name "*.yml" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 6: HTML / PHISHING & WEB ATTACKS
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=6
check_timeout
echo "🌍 Phase 6:  HTML/Phishing & Web Attacks..."

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")

  # 6.1 Phishing forms
  phish=$(grep -nEi '(<form[^>]*(action=|method=['"'"'"'"'"']?post))|password|credit.?card|ssn|social.?security' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$phish" ] && add_finding "MEDIUM" "Phishing form" \
    "$rel: form patterns matching credential harvesting"

  # 6.2 Hidden iframes
  iframe=$(grep -nEi '<iframe[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*['"'"'"'"'"']?[01]['"'"'"'"'"']?|height\s*=\s*['"'"'"'"'"']?[01]['"'"'"'"'"']?)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$iframe" ] && add_finding "HIGH" "Hidden iframe" \
    "$rel: hidden iframe — clickjacking or drive-by download risk"

  # 6.3 Meta refresh redirect
  meta=$(grep -nEi '<meta[^>]+http-equiv\s*=\s*['"'"'"'"'"']?refresh['"'"'"'"'"']?[^>]+url\s*=' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$meta" ] && add_finding "MEDIUM" "Meta refresh redirect" \
    "$rel: auto-redirect via meta refresh"

  # 6.4 External script loading
  ext_script=$(grep -nEi '<script[^>]+src\s*=\s*['"'"'"'"'"'](https?://)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$ext_script" ] && add_finding "MEDIUM" "External script" \
    "$rel: loads scripts from external domain — verify source"

  # 6.5 innerHTML / document.write injection
  inject=$(grep -nEi '(document\.write\s*\(|\.innerHTML\s*[+]?=|insertAdjacentHTML\s*\()' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$inject" ] && add_finding "MEDIUM" "Content injection" \
    "$rel: innerHTML/document.write — XSS surface"

  # 6.6 Tracking pixel (1x1 image)
  pixel=$(grep -nEi '<img[^>]+(width\s*=\s*['"'"'"'"'"']?1['"'"'"'"'"']?[^>]+height\s*=\s*['"'"'"'"'"']?1['"'"'"'"'"']?|height\s*=\s*['"'"'"'"'"']?1['"'"'"'"'"']?[^>]+width\s*=\s*['"'"'"'"'"']?1['"'"'"'"'"']?)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$pixel" ] && add_finding "MEDIUM" "Tracking pixel" \
    "$rel: 1×1 tracking beacon"

  # 6.6 Canvas fingerprinting
  canvas_fp=$(grep -nEi '(canvas\.toDataURL|getImageData|getExtension.*WEBGL|AudioContext.*createOscillator)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$canvas_fp" ] && add_finding "MEDIUM" "Browser fingerprinting" \
    "$rel: canvas/WebGL/audio fingerprinting"

  # 6.7 Brand impersonation in title
  brand_title=$(grep -nEi '<title[^>]*>.*(metamask|phantom|uniswap|opensea|coinbase|binance|trustwallet|ledger|trezor|aave|lido|pancakeswap)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$brand_title" ] && add_finding "HIGH" "Brand impersonation" \
    "$rel: HTML title impersonates known crypto brand"

  # Favicon reference (INFO)
  fav=$(grep -nEi '(rel\s*=\s*['"'"'"'"'"']icon['"'"'"'"'"']|rel\s*=\s*['"'"'"'"'"']shortcut icon['"'"'"'"'"'])' \
    "$f" 2>/dev/null | head -1 || true)
  [ -n "$fav" ] && add_finding "INFO" "Favicon reference" \
    "$rel: verify favicon matches project branding"

done < <(find "$TARGET" \( -name "*.html" -o -name "*.htm" -o -name "*.svg" -o -name "*.php" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# Brand impersonation in image assets
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  fname=$(basename "$f" | tr '[:upper:]' '[:lower:]')
  case "$fname" in
    *metamask*|*phantom*|*uniswap*|*opensea*|*coinbase*|*binance*|*trustwallet*|*ledger*|*trezor*)
      add_finding "HIGH" "Brand impersonation asset" \
        "$rel: asset name matches known crypto brand — possible phishing kit" ;;
  esac
done < <(find "$TARGET" \( -name "*.ico" -o -name "*.png" -o -name "*.svg" \
  -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.gif" -o -name "*.webp" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# manifest.json brand impersonation
for mf in "$TARGET/manifest.json" "$TARGET/public/manifest.json"; do
  if [ -f "$mf" ]; then
    hit=$(grep -Ei '"(name|short_name)"\s*:\s*"[^"]*(metamask|phantom|uniswap|opensea|coinbase|binance|trustwallet|ledger)"' \
      "$mf" 2>/dev/null || true)
    [ -n "$hit" ] && add_finding "HIGH" "Manifest impersonation" \
      "$(echo "$mf" | sed "s|$TARGET/||"): manifest impersonates known brand"
  fi
done

# ════════════════════════════════════════════════════════════════
# PHASE 7: SMART CONTRACT — SOLIDITY
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=7
check_timeout
echo "⬡  Phase 7:  Smart Contract Malicious Patterns (Solidity)..."

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  is_test=false
  case "$rel" in *test*|*Test*|*mock*|*Mock*|*script*) is_test=true ;; esac

  # 7.1 Backdoor patterns
  selfdestruct=$(grep -nEi '\bselfdestruct\b|\bsuicide\b' "$f" 2>/dev/null | head -2 || true)
  [ -n "$selfdestruct" ] && {
    sev="HIGH"; $is_test && sev="MEDIUM"
    add_finding "$sev" "selfdestruct" "$rel: selfdestruct destroys contract and drains ETH"
  }

  deleg=$(grep -nE '\.delegatecall\(' "$f" 2>/dev/null | head -2 || true)
  [ -n "$deleg" ] && add_finding "MEDIUM" "delegatecall" \
    "$rel: delegatecall executes code in contract context"

  lc=$(grep -nE '\.call\{value:' "$f" 2>/dev/null | head -2 || true)
  [ -n "$lc" ] && add_finding "LOW" "Low-level call with value" \
    "$rel: .call{value:} — verify target and calldata"

  # 7.2 Honeypot patterns
  honey=$(grep -nEi '(blacklist\s*\[|isBlacklisted|canSell\s*=\s*false|tradingEnabled\s*=\s*false|maxTxAmount|_isExcluded)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$honey" ] && add_finding "HIGH" "Honeypot indicator" \
    "$rel: blacklist/maxTxAmount/tradingEnabled — common honeypot patterns"

  hidden_fee=$(grep -nE '(setFee|setTax|setBuyFee|setSellFee)\s*\([^)]*\)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$hidden_fee" ] && add_finding "MEDIUM" "Configurable fee" \
    "$rel: fee/tax setter with no visible upper bound — rug-pull vector"

  no_unpause=$(grep -nE 'function\s+pause\b' "$f" 2>/dev/null || true)
  has_unpause=$(grep -nE 'function\s+unpause\b' "$f" 2>/dev/null || true)
  [ -n "$no_unpause" ] && [ -z "$has_unpause" ] && add_finding "HIGH" "Pause without unpause" \
    "$rel: pause() exists but no public unpause() — permanent freeze"

  # 7.1 Admin control (LOW — informational)
  admin=$(grep -nEi '(transferOwnership|renounceOwnership|setOwner|changeAdmin|updateAdmin)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$admin" ] && add_finding "LOW" "Admin control" \
    "$rel: ownership/admin functions — verify access control"

  # 7.4 Token approval abuse
  approval=$(grep -nEi '(approve\s*\(.*MaxUint|approve\s*\(.*115792|setApprovalForAll)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$approval" ] && {
    sev="LOW"; $is_test || sev="MEDIUM"
    add_finding "$sev" "Unlimited approval" "$rel: unlimited token approval — verify intent"
  }

  permit=$(grep -nEi '(EIP712|DOMAIN_SEPARATOR|PERMIT_TYPEHASH|permitTransferFrom)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$permit" ] && add_finding "LOW" "Permit/EIP-712" \
    "$rel: permit signatures — verify no gasless drain"

  # 7.3 Reentrancy surface
  reenter=$(grep -nE '\.call\{' "$f" 2>/dev/null | head -1 || true)
  [ -n "$reenter" ] && add_finding "LOW" "Reentrancy surface" \
    "$rel: external calls present — verify checks-effects-interactions"

  # 7.6 Proxy/upgrade abuse
  upgrade=$(grep -nEi '(upgradeTo\s*\(|upgradeToAndCall\s*\()' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$upgrade" ] && add_finding "MEDIUM" "Upgradeable proxy" \
    "$rel: upgrade functions — verify timelock and access control"

  uups=$(grep -nE 'UUPSUpgradeable' "$f" 2>/dev/null || true)
  auth=$(grep -nE '_authorizeUpgrade' "$f" 2>/dev/null || true)
  [ -n "$uups" ] && [ -z "$auth" ] && add_finding "HIGH" "UUPS without guard" \
    "$rel: UUPSUpgradeable without _authorizeUpgrade override"

  diamond=$(grep -nE 'diamondCut' "$f" 2>/dev/null | head -2 || true)
  [ -n "$diamond" ] && add_finding "MEDIUM" "Diamond proxy" \
    "$rel: diamondCut — verify access control on facet changes"

  # 7.8 Assembly abuse
  asm=$(grep -nE 'assembly\s*\{' "$f" 2>/dev/null | head -2 || true)
  asm_sstore=$(grep -nE '\bsstore\b' "$f" 2>/dev/null | head -2 || true)
  [ -n "$asm_sstore" ] && add_finding "HIGH" "Assembly sstore" \
    "$rel: inline assembly writes to arbitrary storage slots"
  [ -n "$asm" ] && [ -z "$asm_sstore" ] && add_finding "LOW" "Inline assembly" \
    "$rel: inline assembly present — verify safety"

  metamorphic=$(grep -nEi '(selfdestruct|create2)' "$f" 2>/dev/null || true)
  create2=$(grep -nE '\bcreate2\b|\bCREATE2\b' "$f" 2>/dev/null || true)
  [ -n "$metamorphic" ] && [ -n "$create2" ] && add_finding "HIGH" "Metamorphic contract risk" \
    "$rel: selfdestruct + CREATE2 — potential metamorphic contract pattern"

  # 7.10 Known vulnerable patterns
  tx_origin=$(grep -nE 'require\s*\(.*tx\.origin' "$f" 2>/dev/null | head -2 || true)
  [ -n "$tx_origin" ] && add_finding "HIGH" "tx.origin auth" \
    "$rel: tx.origin authentication — phishable, use msg.sender"

  unchecked_call=$(grep -nE '(\.call\s*\(|\.send\s*\()' "$f" 2>/dev/null | head -1 || true)
  checked=$(grep -B1 -A1 -E '(\.call\s*\(|\.send\s*\()' "$f" 2>/dev/null | \
    grep -E '(require|if\s*\(|bool\s+)' 2>/dev/null || true)
  [ -n "$unchecked_call" ] && [ -z "$checked" ] && add_finding "MEDIUM" "Unchecked call return" \
    "$rel: .call()/.send() return value may not be checked"

  old_pragma=$(grep -nE 'pragma solidity.*0\.[0-4]\.' "$f" 2>/dev/null || true)
  [ -n "$old_pragma" ] && add_finding "MEDIUM" "Outdated Solidity" \
    "$rel: Solidity < 0.5 — known compiler bugs"

  float_pragma=$(grep -nE 'pragma solidity\s*\^' "$f" 2>/dev/null || true)
  [ -n "$float_pragma" ] && add_finding "LOW" "Floating pragma" \
    "$rel: floating pragma (^) — pin exact version"

  # Pause + mint combined (LOW — informational)
  pause_gate=$(grep -nEi '(whenPaused|whenNotPaused)' "$f" 2>/dev/null || true)
  hidden_mint=$(grep -nEi '(_mint|_burn)' "$f" 2>/dev/null || true)
  [ -n "$pause_gate" ] && [ -n "$hidden_mint" ] && add_finding "LOW" "Pause-gated mint/burn" \
    "$rel: mint/burn combined with pause — verify intended"

  fallback_body=$(grep -A5 -E '^\s*(fallback|receive)\s*\(' "$f" 2>/dev/null | \
    grep -vE '^\s*(fallback|receive|{|}|\s*$)' || true)
  [ -n "$fallback_body" ] && add_finding "LOW" "Fallback with logic" \
    "$rel: fallback/receive contains logic — reentrancy surface"

  ecrecover_zero=$(grep -nE 'ecrecover' "$f" 2>/dev/null || true)
  zero_check=$(grep -nE 'address\(0\)' "$f" 2>/dev/null || true)
  [ -n "$ecrecover_zero" ] && [ -z "$zero_check" ] && add_finding "HIGH" "ecrecover zero-address" \
    "$rel: ecrecover used without address(0) check — accepts invalid signatures"

done < <(find "$TARGET" -name "*.sol" \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 8: SMART CONTRACT — RUST / SOLANA
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=8
check_timeout
echo "🦀 Phase 8:  Smart Contract Malicious Patterns (Rust/Solana)..."

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")

  # 8.1 Account validation failures
  unchecked=$(grep -nE '(AccountInfo|UncheckedAccount|remaining_accounts)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$unchecked" ] && add_finding "LOW" "Unchecked accounts" \
    "$rel: UncheckedAccount/remaining_accounts — verify all constraints"

  no_signer=$(grep -nE 'AccountInfo' "$f" 2>/dev/null || true)
  has_signer=$(grep -nE '(is_signer|Signer<)' "$f" 2>/dev/null || true)
  [ -n "$no_signer" ] && [ -z "$has_signer" ] && add_finding "MEDIUM" "Missing signer check" \
    "$rel: AccountInfo used without is_signer/Signer constraint"

  # 8.2 PDA seed manipulation
  pda_seeds=$(grep -nE '(seeds\s*=\s*\[.*user_input|seeds.*msg\.sender|seeds.*\bkey\b)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$pda_seeds" ] && add_finding "HIGH" "User-controlled PDA seeds" \
    "$rel: PDA derived from user-controlled input — seed confusion risk"

  no_bump=$(grep -nE 'create_program_address' "$f" 2>/dev/null || true)
  bump_check=$(grep -nE 'bump\s*==|assert.*bump' "$f" 2>/dev/null || true)
  [ -n "$no_bump" ] && [ -z "$bump_check" ] && add_finding "MEDIUM" "Missing bump verification" \
    "$rel: create_program_address without bump seed check"

  # 8.3 CPI abuse
  invoke=$(grep -nE '(invoke_signed\s*\(|invoke\s*\()' "$f" 2>/dev/null | head -2 || true)
  [ -n "$invoke" ] && add_finding "LOW" "CPI invocation" \
    "$rel: cross-program invocation — verify target program IDs"

  arb_cpi=$(grep -nE 'invoke_signed\s*\(\s*&[^,]+,\s*&\[.*to_account_info' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$arb_cpi" ] && add_finding "HIGH" "Arbitrary CPI" \
    "$rel: invoke_signed with user-supplied account — arbitrary program execution risk"

  # 8.4 Token/SOL theft
  close_drain=$(grep -nE 'close\s*=\s*[a-zA-Z_]+' "$f" 2>/dev/null | head -2 || true)
  [ -n "$close_drain" ] && add_finding "MEDIUM" "Account close" \
    "$rel: close constraint drains lamports — verify destination"

  # 8.5 Reinitialization
  reinit=$(grep -nE '(is_initialized|discriminator)' "$f" 2>/dev/null || true)
  init_fn=$(grep -nE 'pub\s+fn\s+initialize' "$f" 2>/dev/null || true)
  [ -n "$init_fn" ] && [ -z "$reinit" ] && add_finding "HIGH" "Reinit attack risk" \
    "$rel: initialize() without is_initialized check — reinitialization attack"

done < <(find "$TARGET" -name "*.rs" \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 9: PYTHON MALICIOUS PATTERNS
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=9
check_timeout
echo "🐍 Phase 9:  Python Malicious Patterns..."

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")

  # 9.1 Code execution
  code_exec=$(grep -nE '\beval\s*\(|\bexec\s*\(|\bcompile\s*\(' "$f" 2>/dev/null | head -2 || true)
  [ -n "$code_exec" ] && add_finding "HIGH" "Python eval/exec" \
    "$rel: eval/exec/compile — arbitrary code execution"

  pickle=$(grep -nE 'pickle\.(loads|load)\s*\(' "$f" 2>/dev/null | head -2 || true)
  [ -n "$pickle" ] && add_finding "HIGH" "pickle.loads" \
    "$rel: pickle deserialization — RCE on untrusted data"

  yaml_unsafe=$(grep -nE 'yaml\.load\s*\(' "$f" 2>/dev/null || true)
  yaml_safe=$(grep -nE 'Loader\s*=\s*.*SafeLoader' "$f" 2>/dev/null || true)
  [ -n "$yaml_unsafe" ] && [ -z "$yaml_safe" ] && add_finding "HIGH" "yaml.load unsafe" \
    "$rel: yaml.load() without SafeLoader — RCE on malicious YAML"

  shell_true=$(grep -nE '(subprocess\.(run|call|Popen|check_output|check_call)|os\.system)\s*\(.*shell\s*=\s*True' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$shell_true" ] && add_finding "HIGH" "subprocess shell=True" \
    "$rel: subprocess with shell=True — command injection risk"

  ctypes=$(grep -nE '(ctypes\.cdll|ctypes\.CDLL|ctypes\.WinDLL)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$ctypes" ] && add_finding "MEDIUM" "ctypes foreign call" \
    "$rel: ctypes loads native library — verify source"

  # 9.2 Setup script abuse
  setup_abuse=$(grep -nE '(cmdclass|class\s+\w+\s*\(\s*(install|develop)\s*\))' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$setup_abuse" ] && add_finding "HIGH" "setup.py hook" \
    "$rel: install/develop class override — executes on pip install"

  # 9.3 Network in __init__.py (runs on import)
  if [[ "$f" == *"__init__.py" ]]; then
    init_net=$(grep -nE '(import\s+requests|import\s+urllib|import\s+socket|import\s+http)' \
      "$f" 2>/dev/null | head -2 || true)
    init_exec=$(grep -nEi '(requests\.(get|post)|urllib|socket\.(connect|create))' \
      "$f" 2>/dev/null | head -2 || true)
    [ -n "$init_exec" ] && add_finding "HIGH" "__init__.py network" \
      "$rel: network calls in __init__.py — executes on module import"
  fi

done < <(find "$TARGET" -name "*.py" \
  -not -path "*/node_modules/*" -not -path "*/target/*" \
  -not -path "*/.tox/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 10: GO MALICIOUS PATTERNS
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=10
check_timeout
echo "🐹 Phase 10: Go Malicious Patterns..."

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")

  # 10.1 Build-time execution
  go_gen=$(grep -nE '^//go:generate' "$f" 2>/dev/null | \
    grep -E '(curl|wget|bash|sh|exec|download)' | head -2 || true)
  [ -n "$go_gen" ] && add_finding "HIGH" "go:generate exec" \
    "$rel: go:generate runs network/shell command"

  init_net=$(grep -A20 'func init\(\)' "$f" 2>/dev/null | \
    grep -E '(net\.Dial|http\.(Get|Post)|exec\.Command)' | head -2 || true)
  [ -n "$init_net" ] && add_finding "HIGH" "init() network/exec" \
    "$rel: init() makes network calls or spawns processes"

  cgo=$(grep -nE '^import\s+"C"' "$f" 2>/dev/null || true)
  cgo_exec=$(grep -nE '//\s*#include|C\.system|C\.popen' "$f" 2>/dev/null | head -2 || true)
  [ -n "$cgo" ] && [ -n "$cgo_exec" ] && add_finding "HIGH" "CGo shell exec" \
    "$rel: CGo with C.system/popen — shell execution"

  # 10.2 Runtime threats
  plugin=$(grep -nE 'plugin\.Open\s*\(' "$f" 2>/dev/null | head -2 || true)
  [ -n "$plugin" ] && add_finding "HIGH" "plugin.Open" \
    "$rel: loads dynamic Go plugin — arbitrary code execution"

  unsafe_ptr=$(grep -nE 'unsafe\.Pointer' "$f" 2>/dev/null | head -2 || true)
  [ -n "$unsafe_ptr" ] && add_finding "MEDIUM" "unsafe.Pointer" \
    "$rel: unsafe pointer manipulation"

  exec_cmd=$(grep -nE 'exec\.Command\s*\(' "$f" 2>/dev/null | head -2 || true)
  [ -n "$exec_cmd" ] && add_finding "MEDIUM" "os/exec command" \
    "$rel: exec.Command() — verify no user-controlled arguments"

done < <(find "$TARGET" -name "*.go" \
  -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 11: DEPENDENCY & SUPPLY CHAIN
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=11
check_timeout
echo "📦 Phase 11: Dependency & Supply Chain..."

if [ -f "$TARGET/package.json" ]; then
  pkg_content=$(cat "$TARGET/package.json" 2>/dev/null)

  # 11.1 Known malicious npm packages
  MALICIOUS_PKGS=(
    "event-stream" "flatmap-stream" "ua-parser-js"
    "colors" "faker" "node-ipc" "peacenotwar" "coa" "rc"
    "crossenv" "cross-env.js" "d3.js" "gruntcli" "http-proxy.js"
    "jquery.js" "mongose" "mysqljs" "node-fabric" "node-opencv"
    "node-opensl" "node-openssl" "nodecaffe" "nodefabric"
    "nodemssql" "noderequest" "nodesass" "nodesqlite" "shadowsock"
    "smb" "sqliter" "sqlserver" "tkinter" "babelcli" "ffmepg"
    "discordi.js" "discord.jss" "electorn" "loadsh" "lodashs"
  )
  for pkg in "${MALICIOUS_PKGS[@]}"; do
    echo "$pkg_content" | grep -q "\"$pkg\"" 2>/dev/null && \
      add_finding "HIGH" "Known-malicious package" \
        "package.json: depends on '$pkg' (known-malicious or typosquat)"
  done

  # 11.2 Suspicious packages (unrelated to smart contracts)
  UNRELATED_PKGS=(
    "puppeteer" "playwright" "selenium-webdriver" "nightmare"
    "nodemailer" "sendgrid" "mailgun" "twilio"
    "express" "koa" "fastify" "hapi"
    "socket.io" "mqtt"
    "sharp" "jimp" "canvas" "fluent-ffmpeg"
    "ssh2" "ftp" "scp2"
    "keylogger" "screenshot-desktop" "robotjs"
  )
  for pkg in "${UNRELATED_PKGS[@]}"; do
    echo "$pkg_content" | grep -q "\"$pkg\"" 2>/dev/null && \
      add_finding "MEDIUM" "Suspicious dependency" \
        "package.json: '$pkg' — unusual for a smart contract repo"
  done

  # 11.4 Git-based dependencies
  git_deps=$(grep -E '"(git\+|git://|github:|bitbucket:|gitlab:)' \
    "$TARGET/package.json" 2>/dev/null || true)
  [ -n "$git_deps" ] && add_finding "MEDIUM" "Git dependencies" \
    "package.json: git-sourced deps bypass npm registry integrity checks"

  # 11.5 Custom registry
  custom_reg=$(grep -E '"registry"\s*:|"publishConfig"' \
    "$TARGET/package.json" 2>/dev/null || true)
  [ -n "$custom_reg" ] && add_finding "MEDIUM" "Custom npm registry" \
    "package.json: non-standard registry URL"

  # 11.6 Outdated versions
  oz_old=$(grep -E '"@openzeppelin/contracts"\s*:\s*"[~^]?[0-3]\.' \
    "$TARGET/package.json" 2>/dev/null || true)
  [ -n "$oz_old" ] && add_finding "MEDIUM" "Outdated OpenZeppelin" \
    "package.json: OpenZeppelin < 4.x — known vulnerabilities"

  old_solc=$(grep -E '"solc"\s*:\s*"[~^]?0\.[0-7]\.' \
    "$TARGET/package.json" 2>/dev/null || true)
  [ -n "$old_solc" ] && add_finding "MEDIUM" "Outdated solc" \
    "package.json: solc < 0.8 — unchecked arithmetic by default"

  # 11.7 Dangerous npm scripts
  dangerous_scripts=$(grep -E '"[^"]+"\s*:\s*"[^"]*\b(rm\s|mv\s|chmod|chown|sudo|node\s+-e|curl\s|wget\s|bash\s|sh\s)' \
    "$TARGET/package.json" 2>/dev/null || true)
  [ -n "$dangerous_scripts" ] && add_finding "MEDIUM" "Dangerous npm script" \
    "package.json: npm scripts with destructive or network commands"

  # Dependency count
  dep_count=$(echo "$pkg_content" | python3 -c "
import sys, json
try:
  p = json.load(sys.stdin)
  print(len(p.get('dependencies',{})) + len(p.get('devDependencies',{})))
except: print(0)
" 2>/dev/null || echo "0")
  [ "$dep_count" -gt 50 ] && add_finding "LOW" "High dependency count" \
    "package.json: $dep_count dependencies — elevated supply chain surface"
fi

# .npmrc custom registry
if [ -f "$TARGET/.npmrc" ]; then
  npmrc_reg=$(grep -E '^registry\s*=' "$TARGET/.npmrc" 2>/dev/null || true)
  [ -n "$npmrc_reg" ] && add_finding "MEDIUM" ".npmrc custom registry" \
    ".npmrc: custom registry — verify source"
fi

# Cargo.toml
if [ -f "$TARGET/Cargo.toml" ]; then
  cargo_content=$(cat "$TARGET/Cargo.toml" 2>/dev/null)
  SUSPICIOUS_CRATES=("soldeer" "tokioo" "abortt" "serdee")
  for crate in "${SUSPICIOUS_CRATES[@]}"; do
    echo "$cargo_content" | grep -q "\"$crate\"" 2>/dev/null && \
      add_finding "HIGH" "Suspicious Rust crate" \
        "Cargo.toml: suspicious crate '$crate'"
  done
  cargo_git=$(grep -E 'git\s*=' "$TARGET/Cargo.toml" 2>/dev/null || true)
  [ -n "$cargo_git" ] && add_finding "MEDIUM" "Cargo git dependency" \
    "Cargo.toml: git-sourced deps bypass crates.io integrity"
fi

# 11.3 Lock file suspicious resolution URLs
for lockfile in "package-lock.json" "yarn.lock" "pnpm-lock.yaml"; do
  if [ -f "$TARGET/$lockfile" ]; then
    suspect_urls=$(grep -Ei 'resolved.*\b(pastebin|raw\.githubusercontent|gist\.github|bit\.ly|tinyurl|t\.co)\b' \
      "$TARGET/$lockfile" 2>/dev/null | head -3 || true)
    [ -n "$suspect_urls" ] && add_finding "HIGH" "Suspicious lock URL" \
      "$lockfile: packages resolved from suspicious URL"
  fi
done

# 11.6 Foundry forge-std version
if [ -f "$TARGET/.gitmodules" ]; then
  forge_old=$(grep -A2 'forge-std' "$TARGET/.gitmodules" 2>/dev/null | \
    grep -E 'branch.*v0\.' || true)
  [ -n "$forge_old" ] && add_finding "LOW" "Old forge-std" \
    ".gitmodules: outdated forge-std — consider updating"
  submod_count=$(grep -c '\[submodule' "$TARGET/.gitmodules" 2>/dev/null || echo "0")
  add_finding "LOW" "Git submodules" \
    "$submod_count submodule(s) — verify all remote origins"
fi

# 11.8 npm audit
if [ -f "$TARGET/package-lock.json" ] && command -v npm &>/dev/null; then
  audit=$(npm audit --json --package-lock-only --prefix "$TARGET" 2>/dev/null || true)
  if [ -n "$audit" ]; then
    crit=$(echo "$audit" | grep -o '"critical":[0-9]*' | head -1 | grep -o '[0-9]*' || echo "0")
    high=$(echo "$audit" | grep -o '"high":[0-9]*' | head -1 | grep -o '[0-9]*' || echo "0")
    [ "$crit" -gt 0 ] 2>/dev/null && add_finding "HIGH" "npm audit: critical" \
      "$crit critical vulnerability(ies) in npm dependencies"
    [ "$high" -gt 0 ] 2>/dev/null && add_finding "MEDIUM" "npm audit: high" \
      "$high high vulnerability(ies) in npm dependencies"
  fi
fi

# ════════════════════════════════════════════════════════════════
# PHASE 12: GIT & REPOSITORY PROFILING
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=12
check_timeout
echo "📜 Phase 12: Git & Repository Profiling..."

if [ -d "$TARGET/.git" ]; then
  first_epoch=$(cd "$TARGET" && git log --reverse --format="%ct" 2>/dev/null | head -1 || echo "0")
  if [ "$first_epoch" -gt 0 ] 2>/dev/null; then
    now_epoch=$(date "+%s")
    age_days=$(( (now_epoch - first_epoch) / 86400 ))
    if [ "$age_days" -lt 7 ]; then
      add_finding "MEDIUM" "New repository" "Repo is ${age_days} day(s) old — high risk"
    elif [ "$age_days" -lt 30 ]; then
      add_finding "LOW" "Recent repository" "Repo is ${age_days} day(s) old"
    fi
  fi

  total_commits=$(cd "$TARGET" && git rev-list --count HEAD 2>/dev/null || echo "0")
  [ "$total_commits" -le 3 ] && add_finding "MEDIUM" "Minimal commit history" \
    "Only $total_commits commit(s) — possible code dump"

  contributor_count=$(cd "$TARGET" && git shortlog -sn --no-merges 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  [ "$contributor_count" -eq 1 ] && add_finding "LOW" "Single contributor" \
    "Only 1 contributor — no peer review history"

  reflog_count=$(cd "$TARGET" && git reflog 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  if [ "$reflog_count" -gt 5 ]; then
    reflog_rewrites=$(cd "$TARGET" && git reflog 2>/dev/null | \
      grep -c "rebase\|reset\|amend" || echo "0")
    [ "$reflog_rewrites" -gt 5 ] && add_finding "LOW" "History rewritten" \
      "$reflog_rewrites rebase/reset/amend events in reflog"
  fi

  # Future-dated commits
  future=$(cd "$TARGET" && git log --format="%ct %H" 2>/dev/null | \
    awk -v now="$(date +%s)" '$1 > now {print $2}' | head -2 || true)
  [ -n "$future" ] && add_finding "MEDIUM" "Future-dated commits" \
    "Commits with timestamps in the future — manipulated timestamps"

  # 12.4 Author profile (INFO)
  unique_authors=$(cd "$TARGET" && git log --format="%ae" 2>/dev/null | sort -u | wc -l | tr -d ' ' || echo "0")
  add_finding "INFO" "Author profile" \
    "$unique_authors unique author(s), $total_commits total commit(s)"

  # 12.5 .gitattributes merge driver abuse
  if [ -f "$TARGET/.gitattributes" ]; then
    merge_driver=$(grep -E 'merge\s*=' "$TARGET/.gitattributes" 2>/dev/null || true)
    [ -n "$merge_driver" ] && add_finding "HIGH" ".gitattributes merge driver" \
      ".gitattributes: custom merge driver — can execute code on git operations"
  fi

  # Git hooks with suspicious content
  while IFS= read -r f; do
    rel=$(echo "$f" | sed "s|$TARGET/||")
    hit=$(grep -nE '(curl |wget |bash |sh |python |exec )' "$f" 2>/dev/null | head -2 || true)
    [ -n "$hit" ] && add_finding "HIGH" "Git hook exec" \
      "$rel: git hook runs network/shell commands"
  done < <(find "$TARGET/.git/hooks" -type f -not -name "*.sample" 2>/dev/null || true)

else
  add_finding "LOW" "No git history" \
    "No .git directory — cannot verify code provenance"
fi

# 12.3 Suspicious filenames (double extension, RTL in name)
while IFS= read -r f; do
  fname=$(basename "$f")
  case "$fname" in
    *.js.exe|*.sol.sh|*.ts.bat|*.py.exe|*.txt.exe)
      add_finding "HIGH" "Double extension" "$(echo "$f" | sed "s|$TARGET/||"): disguised executable" ;;
  esac
done < <(find "$TARGET" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)

# Hidden non-standard files
while IFS= read -r f; do
  base=$(basename "$f")
  case "$base" in
    .env|.env.*|.gitignore|.gitmodules|.gitattributes|.prettierrc*|.solhint*|.eslintrc*|\
    .editorconfig|.npmrc|.nvmrc|.tool-versions|.github|.husky|.vscode|.idea|\
    .DS_Store|.browserslistrc|.babelrc*|.postcssrc*|.stylelintrc*|\
    .rustfmt.toml|.cargo|.solcover*|.gitkeep|.dockerignore|.changeset|\
    .yarn|.yarnrc*|.pnp.*|.node-version|.ruby-version|.python-version|\
    .flake8|.isort.cfg|.mypy.ini|.pylintrc|.clang-format|.swift-format) ;;
    *) add_finding "MEDIUM" "Hidden file" \
         "Non-standard hidden file: $(echo "$f" | sed "s|$TARGET/||")" ;;
  esac
done < <(find "$TARGET" -maxdepth 3 -name ".*" -not -path "*/node_modules/*" \
  -not -path "*/.git/*" -not -path "*/.git" -not -path "*/target/*" \
  -not -path "*/lib/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 13: INFRASTRUCTURE & CONFIGURATION
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=13
check_timeout
echo "🏗️  Phase 13: Infrastructure & Configuration..."

# 13.1 Docker threats
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  privileged=$(grep -nE '\-\-privileged' "$f" 2>/dev/null | head -2 || true)
  [ -n "$privileged" ] && add_finding "HIGH" "Docker --privileged" \
    "$rel: --privileged flag — full host access"

  exposed_secret=$(grep -nE '^\s*ENV\s+\w*(SECRET|PASSWORD|KEY|TOKEN|PASS)\w*\s*=' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$exposed_secret" ] && add_finding "HIGH" "Dockerfile exposed secret" \
    "$rel: secret baked into image ENV layer"

  host_mount=$(grep -nE '(-v\s+/:/|/var/run/docker\.sock|--net(work)?=host)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$host_mount" ] && add_finding "HIGH" "Docker host escape risk" \
    "$rel: host filesystem or docker.sock mount"

  priv_cap=$(grep -nE '(SYS_PTRACE|SYS_ADMIN|SYS_MODULE)' "$f" 2>/dev/null | head -2 || true)
  [ -n "$priv_cap" ] && add_finding "HIGH" "Docker privileged capability" \
    "$rel: SYS_PTRACE/SYS_ADMIN capability — container breakout risk"

done < <(find "$TARGET" \( -name "Dockerfile*" -o -name "docker-compose*.yml" \
  -o -name "docker-compose*.yaml" \) -not -path "*/node_modules/*" 2>/dev/null)

# 13.2 GitHub Actions injection
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  pr_target=$(grep -nE 'on\s*:\s*pull_request_target' "$f" 2>/dev/null | head -2 || true)
  checkout=$(grep -nE 'actions/checkout' "$f" 2>/dev/null | head -2 || true)
  [ -n "$pr_target" ] && [ -n "$checkout" ] && add_finding "HIGH" "PR target injection" \
    "$rel: pull_request_target + checkout — code injection via PR"

  expression_inject=$(grep -nE '\$\{\{\s*github\.event\.(issue\.|pull_request\.|comment\.|discussion\.)?(body|title|name)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$expression_inject" ] && add_finding "HIGH" "Actions expression injection" \
    "$rel: untrusted input in run: step — command injection"

  unpinned=$(grep -nE 'uses:\s*[^@]+@(main|master|latest|v[0-9]+)' \
    "$f" 2>/dev/null | head -3 || true)
  [ -n "$unpinned" ] && add_finding "MEDIUM" "Unpinned Actions" \
    "$rel: third-party action not pinned to commit SHA"

done < <(find "$TARGET/.github/workflows" -name "*.yml" -o -name "*.yaml" 2>/dev/null || true)

# 13.3 Terraform IAM wildcard / open security groups
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  iam_star=$(grep -nE '"Action"\s*:\s*"\*"|actions\s*=\s*\["\*"\]' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$iam_star" ] && add_finding "HIGH" "Terraform IAM wildcard" \
    "$rel: IAM action = * — full permissions"
  sg_open=$(grep -nE '0\.0\.0\.0/0|::/0' "$f" 2>/dev/null | head -2 || true)
  [ -n "$sg_open" ] && add_finding "MEDIUM" "Open security group" \
    "$rel: 0.0.0.0/0 ingress — unrestricted inbound traffic"
  tf_secret=$(grep -nEi '(password|secret|private_key)\s*=\s*"[^"]+"' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$tf_secret" ] && add_finding "HIGH" "Hardcoded Terraform secret" \
    "$rel: hardcoded credential in .tf file"
done < <(find "$TARGET" \( -name "*.tf" -o -name "*.tfvars" \) \
  -not -path "*/node_modules/*" 2>/dev/null)

# 13.4 Foundry / Hardhat config
if [ -f "$TARGET/foundry.toml" ]; then
  ffi=$(grep -E '^\s*ffi\s*=\s*true' "$TARGET/foundry.toml" 2>/dev/null || true)
  [ -n "$ffi" ] && add_finding "MEDIUM" "Forge FFI enabled" \
    "foundry.toml: ffi=true — forge tests can execute shell commands"
fi

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  hit=$(grep -nE '(exec\(|execSync\(|spawn\()' "$f" 2>/dev/null | head -2 || true)
  [ -n "$hit" ] && add_finding "MEDIUM" "Hardhat exec" \
    "$rel: Hardhat config/task spawns external processes"
done < <(find "$TARGET" -maxdepth 2 \( -name "hardhat.config.*" -o -name "*.task.*" \) 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 14: CRYPTOGRAPHIC ABUSE
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=14
check_timeout
echo "🔐 Phase 14: Cryptographic Abuse..."

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")

  # 14.1 Weak/broken ciphers
  weak=$(grep -nEi "(md5|sha1|sha-1|des\b|3des|rc4|arcfour|rot13\s*\()" \
    "$f" 2>/dev/null | grep -Ei "(hash|cipher|crypt|digest|encode|sign)" | head -2 || true)
  [ -n "$weak" ] && add_finding "MEDIUM" "Weak cryptography" \
    "$rel: MD5/SHA1/DES/RC4 — broken for security-sensitive use"

  ecb=$(grep -nEi "(ECB|createCipheriv.*ecb|Cipher.*ECB)" \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$ecb" ] && add_finding "HIGH" "ECB mode" \
    "$rel: ECB cipher mode — does not provide semantic security"

  # Hardcoded IV/key
  hard_iv=$(grep -nE '(iv|key|secret)\s*=\s*['"'"'"]\w{8,}['"'"'"]' \
    "$f" 2>/dev/null | grep -Ei '(iv|key|secret|aes|des)\s*=' | head -2 || true)
  [ -n "$hard_iv" ] && add_finding "HIGH" "Hardcoded crypto key/IV" \
    "$rel: encryption key or IV hardcoded in source"

  # Math.random() for security
  math_rand=$(grep -nE 'Math\.random\s*\(' "$f" 2>/dev/null | \
    grep -Ei '(token|key|secret|nonce|salt|id|otp|pin|password|auth)' | head -2 || true)
  [ -n "$math_rand" ] && add_finding "HIGH" "Math.random() for security" \
    "$rel: Math.random() is not cryptographically secure"

done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" \
  -o -name "*.rs" -o -name "*.go" -o -name "*.java" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 14.1 Solidity: block.timestamp / block.prevrandao as sole randomness
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  rand_ts=$(grep -nE '(block\.timestamp|block\.prevrandao|block\.difficulty)' \
    "$f" 2>/dev/null | \
    grep -Ei '(random|rand|lottery|winner|select|seed|shuffle)' | head -2 || true)
  [ -n "$rand_ts" ] && add_finding "HIGH" "Weak on-chain randomness" \
    "$rel: block.timestamp/prevrandao as randomness source — miner-manipulable"

  # 14.3 Signature replay (missing nonce or chain ID)
  permit_sig=$(grep -nE '(ecrecover\s*\(|ECDSA\.recover\s*\()' "$f" 2>/dev/null | head -2 || true)
  nonce_check=$(grep -nE '(nonce|Nonce)\s*\[' "$f" 2>/dev/null || true)
  chain_id=$(grep -nE 'block\.chainid|CHAIN_ID|chainId' "$f" 2>/dev/null || true)
  if [ -n "$permit_sig" ]; then
    [ -z "$nonce_check" ] && add_finding "HIGH" "Signature replay (no nonce)" \
      "$rel: signature verification without nonce — replay attack"
    [ -z "$chain_id" ] && add_finding "HIGH" "Signature replay (no chain ID)" \
      "$rel: signature verification without chain ID — cross-chain replay"
  fi
done < <(find "$TARGET" -name "*.sol" \
  -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 15: RUNTIME & ENVIRONMENT DETECTION
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=15
check_timeout
echo "⏱️  Phase 15: Runtime & Environment Detection..."

while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")

  # 15.1 Sandbox/VM detection
  webdriver=$(grep -nEi '(navigator\.webdriver|__webdriver__|phantom\.|callPhantom|_phantom|__nightmare)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$webdriver" ] && add_finding "HIGH" "Bot/VM detection" \
    "$rel: checks for WebDriver/PhantomJS/Nightmare — sandbox evasion"

  debugger_det=$(grep -nE '\bdebugger\s*;' "$f" 2>/dev/null | head -2 || true)
  [ -n "$debugger_det" ] && add_finding "MEDIUM" "Debugger detection" \
    "$rel: debugger statement — anti-analysis"

  ci_check=$(grep -nE 'process\.env\.(CI|DOCKER|KUBERNETES|JEST_WORKER|npm_lifecycle_event)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$ci_check" ] && add_finding "MEDIUM" "Env-based branching" \
    "$rel: code branches on CI/Docker env vars — different behavior in sandbox"

done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 15.2 Time bombs and block-based triggers
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  # Block number trigger (specific high block number)
  block_trigger=$(grep -nE 'block\.(number|timestamp)\s*[><=!]+\s*[0-9]{6,}' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$block_trigger" ] && add_finding "HIGH" "Block-based trigger" \
    "$rel: code activates at specific block number/timestamp — time bomb"

  # Date-based trigger in JS
  date_trigger=$(grep -nE '(new Date\(\)|Date\.now\(\))\s*[><=!]+\s*(new Date\(|[0-9]{10,})' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$date_trigger" ] && add_finding "HIGH" "Date-based trigger" \
    "$rel: code activates after a specific date — time bomb"

done < <(find "$TARGET" \( -name "*.sol" -o -name "*.js" -o -name "*.ts" \
  -o -name "*.py" -o -name "*.rs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 16: REACHABILITY & CALL GRAPH
# ════════════════════════════════════════════════════════════════
CURRENT_PHASE=16
check_timeout
echo "🔗 Phase 16: Reachability & Call Graph..."

# 16.1 Orphan files (not imported anywhere)
orphan_count=0
ALL_IMPORTS=$(grep -rE "(import|require\()" "$TARGET" \
  --include="*.js" --include="*.ts" --include="*.sol" \
  --include="*.mjs" --include="*.tsx" --include="*.jsx" \
  2>/dev/null | grep -v "node_modules" || true)

while IFS= read -r f; do
  fname=$(basename "$f" | sed 's/\.[^.]*$//')
  rel=$(echo "$f" | sed "s|$TARGET/||")
  import_refs=$(echo "$ALL_IMPORTS" | grep -F "$fname" | grep -v "$f" | head -1 || true)
  if [ -z "$import_refs" ]; then
    if [[ "$f" == *.sol ]]; then
      sol_refs=$(grep -rlE "import.*${fname}|is\s+${fname}" "$TARGET" \
        --include="*.sol" 2>/dev/null | grep -v "$f" | grep -v "node_modules" | \
        grep -v "lib/" | head -1 || true)
      [ -z "$sol_refs" ] && orphan_count=$((orphan_count + 1))
    else
      orphan_count=$((orphan_count + 1))
    fi
  fi
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.sol" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" \
  -not -path "*/test*" -not -path "*/script*" \
  -not -name "hardhat.config.*" -not -name "index.*" \
  -not -name "main.*" -not -name "deploy.*" 2>/dev/null | head -50)

[ "$orphan_count" -gt 5 ] && add_finding "MEDIUM" "Orphan files" \
  "$orphan_count source files not imported anywhere — possible hidden payloads"
[ "$orphan_count" -gt 0 ] && [ "$orphan_count" -le 5 ] && add_finding "LOW" "Orphan files" \
  "$orphan_count source file(s) not imported by any other file"

# 16.2 Entry point analysis — suspicious public function names
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  sus=$(grep -nE '^\s*function\s+(withdraw|drain|sweep|emergencyWithdraw|execute|multicall|skim|backdoor|exploit|hack|steal|rugPull|honeypot)\s*\([^)]*\)\s*(public|external)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$sus" ] && add_finding "MEDIUM" "Suspicious public function" \
    "$rel: externally callable function with high-risk name"
done < <(find "$TARGET" -name "*.sol" \
  -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null)

# 16.3 Access control gaps
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")

  # Public functions modifying critical state without modifiers
  pub_no_guard=$(grep -nE '^\s*function\s+\w+\s*\([^)]*\)\s*(public|external)\b(?!.*\b(onlyOwner|onlyRole|onlyAdmin|onlyGov|Ownable|require\s*\(msg\.sender))' \
    "$f" 2>/dev/null | grep -Ei '(mint|burn|withdraw|upgrade|set|add|remove|change|update)' | \
    head -2 || true)
  [ -n "$pub_no_guard" ] && add_finding "HIGH" "Unguarded state-change function" \
    "$rel: public/external function with write access and no visible access control"

  # grantRole public (anyone can grant roles)
  open_grant=$(grep -nE 'function\s+grantRole\s*\(' "$f" 2>/dev/null | \
    grep -v "override" | head -2 || true)
  [ -n "$open_grant" ] && add_finding "HIGH" "Public grantRole" \
    "$rel: grantRole() without override — may be callable by anyone"

  # initialize() without onlyInitializing/initializer
  init_fn=$(grep -nE 'function\s+initialize\s*\(' "$f" 2>/dev/null | head -2 || true)
  init_guard=$(grep -nE '(initializer|onlyInitializing)' "$f" 2>/dev/null || true)
  [ -n "$init_fn" ] && [ -z "$init_guard" ] && add_finding "HIGH" "Unguarded initializer" \
    "$rel: initialize() without initializer modifier — anyone can reinitialize proxy"

done < <(find "$TARGET" -name "*.sol" \
  -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null)

# Post-signature drain (JS side)
while IFS= read -r f; do
  rel=$(echo "$f" | sed "s|$TARGET/||")
  post_sig=$(grep -nEi '(signTypedData|personal_sign|eth_sign).*\.then\s*\(|await.*sign.*transfer' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$post_sig" ] && add_finding "HIGH" "Post-signature transfer" \
    "$rel: transfer/drain executes immediately after signature — approval phishing"
  multicall_drain=$(grep -nEi '(multicall|aggregate|batch).*transferFrom|transferFrom.*(multicall|aggregate|batch)' \
    "$f" 2>/dev/null | head -2 || true)
  [ -n "$multicall_drain" ] && add_finding "HIGH" "Multicall drain" \
    "$rel: multicall batched with transferFrom — batch drainer pattern"
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# REPORT
# ════════════════════════════════════════════════════════════════

phase_icon() { [ "$1" = "p" ] && echo "✓" || echo "✗"; }

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🐝 THREAT INTELLIGENCE SCAN RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔴 HIGH:     $HIGH_COUNT"
echo "🟡 MEDIUM:   $MEDIUM_COUNT"
echo "🟢 LOW:      $LOW_COUNT"
echo "ℹ️  INFO:     $INFO_COUNT"
echo ""
echo "── Scan Phases ──────────────────────────────────────────────"
printf "  Phase 1:  Code Execution & Persistence         %s\n" "$(phase_icon $P1)"
printf "  Phase 2:  Network Exfiltration & C2            %s\n" "$(phase_icon $P2)"
printf "  Phase 3:  Obfuscation & Encoding               %s\n" "$(phase_icon $P3)"
printf "  Phase 4:  Credential & Secret Theft            %s\n" "$(phase_icon $P4)"
printf "  Phase 5:  Filesystem & System Access           %s\n" "$(phase_icon $P5)"
printf "  Phase 6:  HTML/Phishing & Web Attacks          %s\n" "$(phase_icon $P6)"
printf "  Phase 7:  Smart Contract Malicious (Solidity)  %s\n" "$(phase_icon $P7)"
printf "  Phase 8:  Smart Contract Malicious (Rust)      %s\n" "$(phase_icon $P8)"
printf "  Phase 9:  Python Malicious Patterns            %s\n" "$(phase_icon $P9)"
printf "  Phase 10: Go Malicious Patterns                %s\n" "$(phase_icon $P10)"
printf "  Phase 11: Dependency & Supply Chain            %s\n" "$(phase_icon $P11)"
printf "  Phase 12: Git & Repository Profiling           %s\n" "$(phase_icon $P12)"
printf "  Phase 13: Infrastructure & Configuration       %s\n" "$(phase_icon $P13)"
printf "  Phase 14: Cryptographic Abuse                  %s\n" "$(phase_icon $P14)"
printf "  Phase 15: Runtime & Environment Detection      %s\n" "$(phase_icon $P15)"
printf "  Phase 16: Reachability & Call Graph            %s\n" "$(phase_icon $P16)"
echo ""

if [ $HIGH_COUNT -gt 0 ]; then
  echo "═══ HIGH SEVERITY ═══"
  for entry in "${HIGH_FINDINGS[@]}"; do echo "  ❌ $entry"; done
  echo ""
fi

if [ $MEDIUM_COUNT -gt 0 ]; then
  echo "═══ MEDIUM SEVERITY ═══"
  for entry in "${MEDIUM_FINDINGS[@]}"; do echo "  ⚠️  $entry"; done
  echo ""
fi

if [ $LOW_COUNT -gt 0 ]; then
  echo "═══ LOW SEVERITY ═══"
  for entry in "${LOW_FINDINGS[@]}"; do echo "  ℹ️  $entry"; done
  echo ""
fi

if [ $INFO_COUNT -gt 0 ]; then
  echo "═══ INFORMATIONAL ═══"
  for entry in "${INFO_FINDINGS[@]}"; do echo "  📋 $entry"; done
  echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $HIGH_COUNT -gt 0 ]; then
  echo "🚫 VERDICT: BLOCKED — $HIGH_COUNT HIGH finding(s). Do NOT proceed."
  echo "   Do not run forge test, npm install, or any build commands."
  exit 20
elif [ $MEDIUM_COUNT -gt 0 ]; then
  echo "⚠️  VERDICT: WARNING — $MEDIUM_COUNT MEDIUM finding(s). Review before proceeding."
  exit 10
else
  echo "✅ VERDICT: CLEAN — No HIGH/MEDIUM findings. Safe to proceed."
  exit 0
fi
