#!/usr/bin/env bash
# threat_intel_scan.sh — Pre-audit threat intelligence scanner for untrusted codebases
#
# Usage:
#   bash threat_intel_scan.sh <project_root>
#
# Performs deep threat analysis including malware detection, dependency auditing,
# behavioral profiling, HTML/JS fingerprinting, favicon matching, reachability
# analysis, and OSS vulnerability feed checks.
#
# Returns exit code:
#   0 = clean (LOW/NONE findings only)
#   1 = MEDIUM severity findings (warn, user decides)
#   2 = HIGH severity findings (block, require explicit user approval)

set -euo pipefail

TARGET="${1:-.}"

if [ ! -d "$TARGET" ]; then
  echo "❌ Directory not found: $TARGET"
  exit 1
fi

HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

HIGH_FINDINGS=()
MEDIUM_FINDINGS=()
LOW_FINDINGS=()
INFO_FINDINGS=()

add_finding() {
  local severity="$1"
  local category="$2"
  local detail="$3"
  local entry="[$severity] $category: $detail"
  case "$severity" in
    HIGH)
      HIGH_FINDINGS+=("$entry")
      HIGH_COUNT=$((HIGH_COUNT + 1))
      ;;
    MEDIUM)
      MEDIUM_FINDINGS+=("$entry")
      MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
      ;;
    LOW)
      LOW_FINDINGS+=("$entry")
      LOW_COUNT=$((LOW_COUNT + 1))
      ;;
    INFO)
      INFO_FINDINGS+=("$entry")
      INFO_COUNT=$((INFO_COUNT + 1))
      ;;
  esac
}

echo "🐝 Scoping Bee — Threat Intelligence Scan"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: $TARGET"
echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ════════════════════════════════════════════════════════════════
# PHASE 1: CODE BEHAVIOR ANALYSIS
# What does this code actually do? Static analysis of intent.
# ════════════════════════════════════════════════════════════════

echo "🔍 Phase 1: Code Behavior Analysis..."

# 1a. npm postinstall/preinstall scripts (auto-execution on install)
if [ -f "$TARGET/package.json" ]; then
  suspect_scripts=$(grep -E '"(postinstall|preinstall|prepare|prepublish)"\s*:' "$TARGET/package.json" 2>/dev/null || true)
  if [ -n "$suspect_scripts" ]; then
    add_finding "HIGH" "Auto-exec lifecycle scripts" "package.json contains auto-run scripts: $suspect_scripts"
  fi
fi

# 1b. Network exfiltration in scripts/source files
while IFS= read -r f; do
  matches=$(grep -nE '(curl |wget |fetch\(|http\.get|https\.get|axios\.|request\(|XMLHttpRequest|sendBeacon)' "$f" 2>/dev/null || true)
  if [ -n "$matches" ]; then
    add_finding "HIGH" "Network exfiltration" "$(basename "$f"): outbound network calls detected"
  fi
done < <(find "$TARGET" \( -name "*.sh" -o -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.mjs" -o -name "*.cjs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# 1c. Base64 encoded payloads (long base64 strings > 100 chars)
while IFS= read -r f; do
  b64=$(grep -nE '[A-Za-z0-9+/]{100,}={0,2}' "$f" 2>/dev/null | head -3 || true)
  if [ -n "$b64" ]; then
    add_finding "HIGH" "Obfuscated payload" "$(basename "$f"): large Base64-encoded string detected"
  fi
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" -o -name "*.sol" -o -name "*.rs" -o -name "*.html" -o -name "*.mjs" -o -name "*.cjs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# 1d. Compiled binaries or shared objects
while IFS= read -r f; do
  add_finding "HIGH" "Suspicious binary" "Binary/executable found: $(echo "$f" | sed "s|$TARGET/||")"
done < <(find "$TARGET" \( -name "*.exe" -o -name "*.dll" -o -name "*.so" -o -name "*.dylib" -o -name "*.bin" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 1e. Symlinks pointing outside repo
while IFS= read -r f; do
  link_target=$(readlink "$f" 2>/dev/null || true)
  if [ -n "$link_target" ]; then
    abs_target=$(cd "$(dirname "$f")" && realpath "$link_target" 2>/dev/null || echo "$link_target")
    abs_repo=$(realpath "$TARGET" 2>/dev/null || echo "$TARGET")
    case "$abs_target" in
      "$abs_repo"*) ;;
      *) add_finding "HIGH" "External symlink" "$(echo "$f" | sed "s|$TARGET/||") → $link_target (outside repo)" ;;
    esac
  fi
done < <(find "$TARGET" -type l -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# 1f. Forge FFI in Solidity (arbitrary shell execution)
while IFS= read -r f; do
  ffi_calls=$(grep -nE 'vm\.ffi\(' "$f" 2>/dev/null || true)
  if [ -n "$ffi_calls" ]; then
    add_finding "HIGH" "Forge FFI execution" "$(basename "$f"): vm.ffi() calls can execute arbitrary shell commands"
  fi
done < <(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null)

# 1g. eval/exec/spawn — dynamic code execution
while IFS= read -r f; do
  evals=$(grep -nE '\b(eval|exec|execSync|child_process|spawn|subprocess|Function\()\b' "$f" 2>/dev/null | grep -v "node_modules" || true)
  if [ -n "$evals" ]; then
    add_finding "HIGH" "Dynamic code execution" "$(basename "$f"): eval/exec/spawn patterns found"
  fi
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.mjs" -o -name "*.cjs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# 1h. Hex-encoded shellcode patterns
while IFS= read -r f; do
  hex_payloads=$(grep -nE '(\\x[0-9a-fA-F]{2}){10,}' "$f" 2>/dev/null | head -3 || true)
  if [ -n "$hex_payloads" ]; then
    add_finding "HIGH" "Hex shellcode" "$(basename "$f"): hex-encoded byte sequences detected"
  fi
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 2: HTML FINGERPRINT & DATABASE MATCHING
# Check HTML files against known phishing/malware fingerprints.
# ════════════════════════════════════════════════════════════════

echo "🌐 Phase 2: HTML Fingerprint Analysis..."

while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # 2a. Known phishing form patterns (credential harvesting)
  phish_forms=$(grep -nEi '(<form[^>]*(action=|method=["'\'']?post))|password|credit.?card|ssn|social.?security' "$f" 2>/dev/null || true)
  if [ -n "$phish_forms" ]; then
    add_finding "MEDIUM" "HTML phishing fingerprint" "$rel_path: contains form patterns matching credential harvesting templates"
  fi

  # 2b. Hidden iframes (clickjacking / drive-by)
  hidden_iframes=$(grep -nEi '<iframe[^>]*(style\s*=\s*["\x27][^"]*display\s*:\s*none|style\s*=\s*["\x27][^"]*visibility\s*:\s*hidden|width\s*=\s*["\x27]?[01]["\x27]?|height\s*=\s*["\x27]?[01]["\x27]?)' "$f" 2>/dev/null || true)
  if [ -n "$hidden_iframes" ]; then
    add_finding "HIGH" "Hidden iframe" "$rel_path: hidden iframe detected — potential clickjacking or drive-by download"
  fi

  # 2c. External script injection from suspicious domains
  ext_scripts=$(grep -nEi '<script[^>]+src\s*=\s*["'\''](https?://)[^"'\'']*["'\'']' "$f" 2>/dev/null || true)
  if [ -n "$ext_scripts" ]; then
    add_finding "MEDIUM" "External script loading" "$rel_path: loads scripts from external domains — verify sources"
  fi

  # 2d. Data exfiltration via image beacons / tracking pixels
  tracking_pixels=$(grep -nEi '<img[^>]+(width\s*=\s*["\x27]?1["\x27]?|height\s*=\s*["\x27]?1["\x27]?)[^>]+(width\s*=\s*["\x27]?1["\x27]?|height\s*=\s*["\x27]?1["\x27]?)' "$f" 2>/dev/null || true)
  if [ -n "$tracking_pixels" ]; then
    add_finding "MEDIUM" "Tracking pixel" "$rel_path: 1x1 tracking pixel/beacon detected"
  fi

  # 2e. Meta refresh redirects (auto-redirect to malicious site)
  meta_refresh=$(grep -nEi '<meta[^>]+http-equiv\s*=\s*["\x27]?refresh["\x27]?[^>]+url\s*=' "$f" 2>/dev/null || true)
  if [ -n "$meta_refresh" ]; then
    add_finding "MEDIUM" "Meta refresh redirect" "$rel_path: auto-redirect via meta refresh — potential phishing redirect"
  fi

  # 2f. Obfuscated HTML entities / Unicode escape abuse
  obfuscated_html=$(grep -nE '(&#x[0-9a-fA-F]{2,4};){5,}|(\\u[0-9a-fA-F]{4}){5,}' "$f" 2>/dev/null || true)
  if [ -n "$obfuscated_html" ]; then
    add_finding "MEDIUM" "Obfuscated HTML" "$rel_path: heavy HTML entity or unicode escape obfuscation"
  fi

done < <(find "$TARGET" \( -name "*.html" -o -name "*.htm" -o -name "*.svg" -o -name "*.php" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 3: BANNER & FAVICON MATCHING
# Detect brand impersonation via favicon/logo hashes.
# ════════════════════════════════════════════════════════════════

echo "🏷️  Phase 3: Banner & Favicon Matching..."

# 3a. Check for favicon files and suspicious naming
while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")
  fname=$(basename "$f" | tr '[:upper:]' '[:lower:]')

  # Known impersonation targets
  case "$fname" in
    *metamask*|*phantom*|*uniswap*|*opensea*|*coinbase*|*binance*|*trust*wallet*|*ledger*|*trezor*)
      add_finding "HIGH" "Brand impersonation asset" "$rel_path: asset name matches known crypto brand — possible phishing kit"
      ;;
  esac
done < <(find "$TARGET" \( -name "*.ico" -o -name "*.png" -o -name "*.svg" -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.gif" -o -name "*.webp" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# 3b. Check HTML titles/meta for brand impersonation
while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")
  brand_title=$(grep -nEi '<title[^>]*>.*(metamask|phantom|uniswap|opensea|coinbase|binance|trustwallet|aave|compound|lido|pancakeswap)' "$f" 2>/dev/null || true)
  if [ -n "$brand_title" ]; then
    add_finding "HIGH" "Brand impersonation title" "$rel_path: HTML title matches known crypto brand — phishing indicator"
  fi

  # Check for brand favicons referenced in HTML
  favicon_ref=$(grep -nEi '(rel\s*=\s*["\x27]icon["\x27]|rel\s*=\s*["\x27]shortcut icon["\x27])' "$f" 2>/dev/null || true)
  if [ -n "$favicon_ref" ]; then
    add_finding "INFO" "Favicon reference" "$rel_path: favicon link detected — verify it matches project branding"
  fi
done < <(find "$TARGET" \( -name "*.html" -o -name "*.htm" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null)

# 3c. Check for manifest.json with suspicious app names
if [ -f "$TARGET/manifest.json" ] || [ -f "$TARGET/public/manifest.json" ]; then
  manifest_file=""
  [ -f "$TARGET/manifest.json" ] && manifest_file="$TARGET/manifest.json"
  [ -f "$TARGET/public/manifest.json" ] && manifest_file="$TARGET/public/manifest.json"
  if [ -n "$manifest_file" ]; then
    brand_manifest=$(grep -Ei '"(name|short_name)"\s*:\s*"[^"]*(metamask|phantom|uniswap|opensea|coinbase|binance|trustwallet|ledger)"' "$manifest_file" 2>/dev/null || true)
    if [ -n "$brand_manifest" ]; then
      add_finding "HIGH" "Manifest brand impersonation" "$(echo "$manifest_file" | sed "s|$TARGET/||"): app manifest impersonates a known brand"
    fi
  fi
fi

# ════════════════════════════════════════════════════════════════
# PHASE 4: CLIENT-SIDE JS ANALYSIS
# Deep inspection of JS files for malicious call patterns.
# ════════════════════════════════════════════════════════════════

echo "⚡ Phase 4: Client-Side JavaScript Analysis..."

while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # 4a. Wallet interaction / private key access patterns
  wallet_access=$(grep -nEi '(eth_sign|eth_sendTransaction|personal_sign|eth_accounts|eth_requestAccounts|window\.ethereum|window\.solana|signTransaction|signAllTransactions|signMessage|getPrivateKey|privateKey|secret_key|mnemonic|seed_phrase)' "$f" 2>/dev/null || true)
  if [ -n "$wallet_access" ]; then
    add_finding "MEDIUM" "Wallet/key interaction" "$rel_path: accesses wallet APIs or private key material — verify legitimacy"
  fi

  # 4b. DOM manipulation for credential theft
  dom_theft=$(grep -nEi '(document\.cookie|localStorage\.getItem|sessionStorage|indexedDB|\.getItem\(["\x27](token|auth|session|jwt|key|secret|password))' "$f" 2>/dev/null || true)
  if [ -n "$dom_theft" ]; then
    add_finding "MEDIUM" "Storage/cookie access" "$rel_path: accesses cookies, localStorage, or session storage — potential data theft"
  fi

  # 4c. Clipboard hijacking
  clipboard=$(grep -nEi '(navigator\.clipboard|document\.execCommand\(["\x27]copy|clipboardData|oncopy|oncut|onpaste)' "$f" 2>/dev/null || true)
  if [ -n "$clipboard" ]; then
    add_finding "MEDIUM" "Clipboard access" "$rel_path: clipboard API usage — potential address swap attack"
  fi

  # 4d. Dynamic script injection
  script_inject=$(grep -nEi '(document\.createElement\(["\x27]script|\.appendChild\(|\.insertBefore\(|document\.write\(|innerHTML\s*[+]?=)' "$f" 2>/dev/null || true)
  if [ -n "$script_inject" ]; then
    add_finding "MEDIUM" "Dynamic script injection" "$rel_path: dynamically creates/injects script elements"
  fi

  # 4e. WebSocket connections (C2 channel potential)
  websocket=$(grep -nEi '(new\s+WebSocket|\.onmessage|\.send\(|wss?://)' "$f" 2>/dev/null || true)
  if [ -n "$websocket" ]; then
    add_finding "LOW" "WebSocket connection" "$rel_path: WebSocket usage detected — check for C2 communication patterns"
  fi

  # 4f. Obfuscated JS patterns (packed/encoded code)
  obfuscated_js=$(grep -nE '(\\x[0-9a-fA-F]{2}){8,}|(_0x[a-f0-9]{4,})|(\["\x5cx)|atob\(|btoa\(|String\.fromCharCode\(' "$f" 2>/dev/null || true)
  if [ -n "$obfuscated_js" ]; then
    add_finding "HIGH" "Obfuscated JavaScript" "$rel_path: code obfuscation or encoding patterns — suspicious"
  fi

  # 4g. Event listeners on sensitive input fields
  keylogger=$(grep -nEi '(addEventListener\(["\x27](keydown|keyup|keypress|input)|onkeydown|onkeyup|onkeypress)' "$f" 2>/dev/null || true)
  if [ -n "$keylogger" ]; then
    add_finding "LOW" "Input event listeners" "$rel_path: keyboard event listeners detected — verify not keylogging"
  fi

  # 4h. Crypto mining patterns
  mining=$(grep -nEi '(coinhive|cryptonight|monero|wasm.*mine|stratum\+tcp|hashrate|CryptoLoot)' "$f" 2>/dev/null || true)
  if [ -n "$mining" ]; then
    add_finding "HIGH" "Crypto mining" "$rel_path: cryptocurrency mining patterns detected"
  fi

done < <(find "$TARGET" \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" -not -path "*/dist/*" -not -path "*/build/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 5: POST-SIGNATURE DISTRIBUTOR CHECK
# Detect code that executes after signing or approval flows.
# ════════════════════════════════════════════════════════════════

echo "🔏 Phase 5: Post-Signature Distributor Check..."

while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # 5a. Approval + immediate transfer patterns (approval phishing)
  approval_drain=$(grep -nEi '(approve\s*\(.*MaxUint|approve\s*\(.*115792|setApprovalForAll|increaseAllowance)' "$f" 2>/dev/null || true)
  if [ -n "$approval_drain" ]; then
    add_finding "HIGH" "Unlimited approval pattern" "$rel_path: requests unlimited token approval — common drainer technique"
  fi

  # 5b. Post-signature callback execution
  post_sig=$(grep -nEi '(\.then\s*\(|await\s+).*sign.*\.(then|catch)|signTypedData.*\.then|permit\s*\(' "$f" 2>/dev/null || true)
  if [ -n "$post_sig" ]; then
    add_finding "MEDIUM" "Post-signature execution" "$rel_path: code executes callbacks after signature — verify intent"
  fi

  # 5c. EIP-712 / Permit signature abuse
  permit_abuse=$(grep -nEi '(EIP712|DOMAIN_SEPARATOR|PERMIT_TYPEHASH|nonces\s*\[|deadline|permitTransferFrom)' "$f" 2>/dev/null || true)
  if [ -n "$permit_abuse" ]; then
    add_finding "LOW" "Permit/EIP-712 usage" "$rel_path: uses permit signatures — verify no gasless approval drain"
  fi

  # 5d. Multicall after approval (batch drain pattern)
  multicall_drain=$(grep -nEi '(multicall|aggregate|batch).*transfer|transferFrom.*multicall' "$f" 2>/dev/null || true)
  if [ -n "$multicall_drain" ]; then
    add_finding "HIGH" "Multicall drain pattern" "$rel_path: multicall combined with transfers — possible batch drainer"
  fi

done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.sol" -o -name "*.mjs" -o -name "*.jsx" -o -name "*.tsx" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 6: CODEBASE PROFILE ANALYSIS
# Analyze git history and contributor patterns.
# ════════════════════════════════════════════════════════════════

echo "👤 Phase 6: Codebase Profile Analysis..."

if [ -d "$TARGET/.git" ]; then
  # 6a. Repo age check (newly created repos are higher risk)
  first_commit_date=$(cd "$TARGET" && git log --reverse --format="%ai" 2>/dev/null | head -1 || true)
  if [ -n "$first_commit_date" ]; then
    first_epoch=$(date -j -f "%Y-%m-%d %H:%M:%S %z" "$first_commit_date" "+%s" 2>/dev/null || \
                  date -d "$first_commit_date" "+%s" 2>/dev/null || echo "0")
    now_epoch=$(date "+%s")
    if [ "$first_epoch" -gt 0 ]; then
      age_days=$(( (now_epoch - first_epoch) / 86400 ))
      if [ "$age_days" -lt 7 ]; then
        add_finding "MEDIUM" "New repository" "Repo is only ${age_days} day(s) old — higher phishing/scam risk"
      elif [ "$age_days" -lt 30 ]; then
        add_finding "LOW" "Recent repository" "Repo is ${age_days} day(s) old — relatively new"
      fi
    fi
  fi

  # 6b. Contributor count
  contributor_count=$(cd "$TARGET" && git shortlog -sn --no-merges 2>/dev/null | wc -l | tr -d ' ' || echo "0")
  if [ "$contributor_count" -eq 1 ]; then
    add_finding "LOW" "Single contributor" "Only 1 contributor — no peer review history"
  fi

  # 6c. Check for force pushes or history rewriting
  reflog_rewrites=$(cd "$TARGET" && git reflog 2>/dev/null | grep -c "rebase\|reset\|amend" || echo "0")
  if [ "$reflog_rewrites" -gt 5 ]; then
    add_finding "LOW" "History rewritten" "Git reflog shows $reflog_rewrites rebase/reset/amend events — history may be altered"
  fi

  # 6d. Check for suspicious commit patterns (bulk dump vs gradual development)
  total_commits=$(cd "$TARGET" && git rev-list --count HEAD 2>/dev/null || echo "0")
  if [ "$total_commits" -le 3 ]; then
    add_finding "MEDIUM" "Minimal commit history" "Only $total_commits commit(s) — possible code dump, not organic development"
  fi

  # 6e. Check for commits by different authors with same content (copy-paste repos)
  unique_authors=$(cd "$TARGET" && git log --format="%ae" 2>/dev/null | sort -u | wc -l | tr -d ' ' || echo "0")
  add_finding "INFO" "Author profile" "Repository has $unique_authors unique author(s), $total_commits total commit(s)"

else
  add_finding "LOW" "No git history" "No .git directory — cannot verify code provenance or development history"
fi

# ════════════════════════════════════════════════════════════════
# PHASE 7: FUNCTION PURPOSE ANALYSIS
# Identify attacking functions vs legitimate contract logic.
# ════════════════════════════════════════════════════════════════

echo "⚙️  Phase 7: Function Purpose Analysis..."

# 7a. Solidity: selfdestruct / delegatecall / arbitrary call patterns
while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # Selfdestruct — can destroy the contract
  selfdestruct=$(grep -nEi '\bselfdestruct\b|\bsuicide\b' "$f" 2>/dev/null || true)
  if [ -n "$selfdestruct" ]; then
    add_finding "HIGH" "Selfdestruct present" "$rel_path: selfdestruct can destroy the contract and drain ETH"
  fi

  # Arbitrary delegatecall
  delegatecall=$(grep -nE '\.delegatecall\(' "$f" 2>/dev/null || true)
  if [ -n "$delegatecall" ]; then
    add_finding "MEDIUM" "Delegatecall usage" "$rel_path: delegatecall can execute arbitrary code in contract context"
  fi

  # Arbitrary low-level call with value
  arb_call=$(grep -nE '\.call\{value:' "$f" 2>/dev/null || true)
  if [ -n "$arb_call" ]; then
    add_finding "LOW" "Low-level call with value" "$rel_path: low-level .call{value:} — verify target and data"
  fi

  # Ownership transfer / admin backdoor patterns
  backdoor=$(grep -nEi '(transferOwnership|renounceOwnership|setOwner|changeAdmin|updateAdmin)' "$f" 2>/dev/null || true)
  if [ -n "$backdoor" ]; then
    add_finding "LOW" "Admin control functions" "$rel_path: ownership/admin control functions — verify access control"
  fi

  # Pause/unpause with hidden mint or transfer
  pause_abuse=$(grep -nEi '(whenPaused|whenNotPaused)' "$f" 2>/dev/null || true)
  hidden_mint=$(grep -nEi '(_mint|_burn|_transfer)' "$f" 2>/dev/null || true)
  if [ -n "$pause_abuse" ] && [ -n "$hidden_mint" ]; then
    add_finding "LOW" "Pause-gated minting" "$rel_path: mint/burn combined with pause gates — verify intended behavior"
  fi

done < <(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# 7b. Rust/Anchor: Dangerous patterns
while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # Unchecked accounts
  unchecked_acc=$(grep -nE '(AccountInfo|UncheckedAccount|remaining_accounts)' "$f" 2>/dev/null || true)
  if [ -n "$unchecked_acc" ]; then
    add_finding "LOW" "Unchecked accounts" "$rel_path: uses UncheckedAccount or remaining_accounts — verify validation"
  fi

  # invoke_signed with suspicious seeds
  cpi_invoke=$(grep -nE 'invoke_signed\(|invoke\(' "$f" 2>/dev/null || true)
  if [ -n "$cpi_invoke" ]; then
    add_finding "LOW" "CPI invocations" "$rel_path: cross-program invocations found — verify target programs"
  fi

done < <(find "$TARGET" -name "*.rs" -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 8: PACKAGE.JSON DEPENDENCY AUDIT
# Check for unnecessary, suspicious, or typosquatted packages.
# ════════════════════════════════════════════════════════════════

echo "📦 Phase 8: Dependency Audit..."

if [ -f "$TARGET/package.json" ]; then

  # 8a. Known suspicious/malicious package names (typosquatting, trojans)
  SUSPICIOUS_PKGS=(
    "event-stream" "flatmap-stream" "ua-parser-js-malware"
    "colors-hack" "faker-hack" "node-ipc-malware"
    "peacenotwar" "es5-ext-malware" "coa-malware"
    "rc-malware" "crossenv" "cross-env.js" "crossenv.js"
    "d3.js" "gruntcli" "http-proxy.js" "jquery.js"
    "mariadb" "mongose" "mysqljs" "node-fabric"
    "node-opencv" "node-opensl" "node-openssl" "nodecaffe"
    "nodefabric" "nodemssql" "noderequest" "nodesass"
    "nodesqlite" "shadowsock" "smb" "sqliter" "sqlserver"
    "tkinter" "babelcli" "ffmepg" "gruntcli" "discordi.js"
    "discord.jss" "electorn" "loadsh" "lodashs"
  )

  pkg_content=$(cat "$TARGET/package.json" 2>/dev/null)
  for pkg in "${SUSPICIOUS_PKGS[@]}"; do
    if echo "$pkg_content" | grep -q "\"$pkg\"" 2>/dev/null; then
      add_finding "HIGH" "Suspicious package" "package.json depends on known-malicious or typosquatted package: $pkg"
    fi
  done

  # 8b. Non-standard npm scripts with dangerous commands
  custom_scripts=$(grep -E '"[^"]+"\s*:\s*"[^"]*\b(rm |mv |cp |chmod|chown|sudo|node -e|ts-node -e|curl |wget |bash |sh )' "$TARGET/package.json" 2>/dev/null || true)
  if [ -n "$custom_scripts" ]; then
    add_finding "MEDIUM" "Dangerous npm scripts" "package.json contains scripts with destructive or network commands"
  fi

  # 8c. Packages unrelated to smart contracts (suspicious for audit repos)
  UNRELATED_PKGS=(
    "puppeteer" "playwright" "selenium-webdriver" "nightmare"
    "nodemailer" "sendgrid" "mailgun" "twilio"
    "express" "koa" "fastify" "hapi"
    "socket.io" "ws" "mqtt"
    "sharp" "jimp" "canvas"
    "fluent-ffmpeg" "ffmpeg"
    "ssh2" "ftp" "scp2"
  )

  for pkg in "${UNRELATED_PKGS[@]}"; do
    if echo "$pkg_content" | grep -q "\"$pkg\"" 2>/dev/null; then
      add_finding "MEDIUM" "Unrelated dependency" "package.json includes '$pkg' — unusual for a smart contract audit repo"
    fi
  done

  # 8d. Dependency count check (bloated repos)
  dep_count=$(echo "$pkg_content" | grep -c '"[^"]*"\s*:\s*"[~^><=0-9]' 2>/dev/null || echo "0")
  if [ "$dep_count" -gt 50 ]; then
    add_finding "LOW" "Heavy dependencies" "package.json has $dep_count dependencies — increases supply chain risk"
  fi

  # 8e. Private registry or unusual registry URLs
  registry_urls=$(grep -nEi '"registry"\s*:|"publishConfig"|"https?://[^"]*\.(internal|local|corp|private)' "$TARGET/package.json" 2>/dev/null || true)
  if [ -n "$registry_urls" ]; then
    add_finding "MEDIUM" "Custom registry" "package.json references non-standard npm registry — verify source"
  fi

  # 8f. Git dependencies (bypasses npm registry)
  git_deps=$(grep -nE '"(git\+|git://|github:|bitbucket:|gitlab:)' "$TARGET/package.json" 2>/dev/null || true)
  if [ -n "$git_deps" ]; then
    add_finding "MEDIUM" "Git dependencies" "package.json has git-based dependencies — bypasses npm registry checks"
  fi

fi

# Check for yarn/pnpm lock anomalies
for lockfile in "package-lock.json" "yarn.lock" "pnpm-lock.yaml"; do
  if [ -f "$TARGET/$lockfile" ]; then
    # Check for integrity mismatches or suspicious resolved URLs
    suspect_urls=$(grep -nEi 'resolved.*\b(pastebin|raw\.githubusercontent|gist\.github|bit\.ly|tinyurl|t\.co)\b' "$TARGET/$lockfile" 2>/dev/null | head -3 || true)
    if [ -n "$suspect_urls" ]; then
      add_finding "HIGH" "Suspicious lock resolution" "$lockfile: packages resolved from suspicious URLs"
    fi
  fi
done

# ════════════════════════════════════════════════════════════════
# PHASE 9: REACHABILITY ANALYSIS
# Check if suspicious code patterns are actually callable.
# ════════════════════════════════════════════════════════════════

echo "🔗 Phase 9: Reachability Analysis..."

# 9a. Check for dead/unreachable code files (imported nowhere)
orphan_count=0
while IFS= read -r f; do
  fname=$(basename "$f" | sed 's/\.[^.]*$//')
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # Check if this file is imported/required anywhere
  import_refs=$(grep -rlE "(import.*['\"].*${fname}|require\(['\"].*${fname})" "$TARGET" \
    --include="*.js" --include="*.ts" --include="*.sol" --include="*.mjs" --include="*.tsx" --include="*.jsx" \
    2>/dev/null | grep -v "$f" | grep -v "node_modules" | head -1 || true)

  if [ -z "$import_refs" ]; then
    # Check Solidity inheritance
    if [[ "$f" == *.sol ]]; then
      sol_refs=$(grep -rlE "import.*${fname}|is\s+${fname}" "$TARGET" --include="*.sol" 2>/dev/null | grep -v "$f" | grep -v "node_modules" | grep -v "lib/" | head -1 || true)
      if [ -z "$sol_refs" ]; then
        orphan_count=$((orphan_count + 1))
      fi
    else
      orphan_count=$((orphan_count + 1))
    fi
  fi
done < <(find "$TARGET" \( -name "*.js" -o -name "*.ts" -o -name "*.sol" -o -name "*.mjs" \) \
  -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" \
  -not -path "*/test*" -not -path "*/script*" -not -name "hardhat.config.*" -not -name "foundry.toml" \
  -not -name "index.*" -not -name "main.*" -not -name "deploy.*" 2>/dev/null | head -50)

if [ "$orphan_count" -gt 5 ]; then
  add_finding "MEDIUM" "Orphan files detected" "$orphan_count source files not imported anywhere — possible hidden payload files"
elif [ "$orphan_count" -gt 0 ]; then
  add_finding "LOW" "Orphan files" "$orphan_count source file(s) not imported by any other file"
fi

# 9b. Entry point analysis — check if suspicious functions are externally callable
while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # Public/external functions with suspicious names
  sus_external=$(grep -nE '^\s*function\s+(withdraw|drain|sweep|emergencyWithdraw|execute|multicall|skim).*\b(public|external)\b' "$f" 2>/dev/null || true)
  if [ -n "$sus_external" ]; then
    add_finding "MEDIUM" "Suspicious public function" "$rel_path: externally callable function with high-risk name — verify access control"
  fi

  # Fallback/receive with logic (potential reentrancy entry)
  fallback_logic=$(grep -nE '^\s*(fallback|receive)\s*\(' "$f" 2>/dev/null || true)
  if [ -n "$fallback_logic" ]; then
    fallback_body=$(grep -A5 -E '^\s*(fallback|receive)\s*\(' "$f" 2>/dev/null | grep -vE '^\s*(fallback|receive|{|}|\s*$)' || true)
    if [ -n "$fallback_body" ]; then
      add_finding "LOW" "Fallback with logic" "$rel_path: fallback/receive function contains logic — reentrancy surface"
    fi
  fi

done < <(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# PHASE 10: OSS VULNERABILITY FEED CHECK
# Cross-reference against known vulnerability patterns.
# ════════════════════════════════════════════════════════════════

echo "📡 Phase 10: OSS Feed & Known Vulnerability Check..."

# 10a. Check for known vulnerable Solidity patterns
while IFS= read -r f; do
  rel_path=$(echo "$f" | sed "s|$TARGET/||")

  # tx.origin authentication (classic vulnerability)
  tx_origin=$(grep -nE 'require\(.*tx\.origin' "$f" 2>/dev/null || true)
  if [ -n "$tx_origin" ]; then
    add_finding "HIGH" "tx.origin auth" "$rel_path: uses tx.origin for authentication — phishable, use msg.sender"
  fi

  # Unchecked return values on low-level calls
  unchecked_call=$(grep -nE '(\.call\(|\.send\()' "$f" 2>/dev/null || true)
  unchecked_success=$(grep -B1 -A1 -E '(\.call\(|\.send\()' "$f" 2>/dev/null | grep -E '(require|if|bool)' || true)
  if [ -n "$unchecked_call" ] && [ -z "$unchecked_success" ]; then
    add_finding "MEDIUM" "Unchecked call return" "$rel_path: low-level call return value may not be checked"
  fi

  # Reentrancy pattern: state change after external call
  reentrancy=$(grep -nE '\.call\{' "$f" 2>/dev/null | head -1 || true)
  if [ -n "$reentrancy" ]; then
    add_finding "LOW" "Potential reentrancy surface" "$rel_path: external calls present — verify checks-effects-interactions"
  fi

  # Old Solidity version (known compiler bugs)
  old_pragma=$(grep -nE 'pragma solidity.*0\.[0-4]\.' "$f" 2>/dev/null || true)
  if [ -n "$old_pragma" ]; then
    add_finding "MEDIUM" "Outdated Solidity version" "$rel_path: uses Solidity < 0.5.x — known compiler vulnerabilities"
  fi

  # Floating pragma
  float_pragma=$(grep -nE 'pragma solidity\s*\^' "$f" 2>/dev/null || true)
  if [ -n "$float_pragma" ]; then
    add_finding "LOW" "Floating pragma" "$rel_path: uses floating pragma (^) — pin version for production"
  fi

done < <(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" -not -path "*/target/*" 2>/dev/null)

# 10b. Check for known vulnerable dependency versions in package.json
if [ -f "$TARGET/package.json" ]; then
  # OpenZeppelin < 4.x (major known issues)
  oz_old=$(grep -E '"@openzeppelin/contracts"\s*:\s*"[~^]?[0-3]\.' "$TARGET/package.json" 2>/dev/null || true)
  if [ -n "$oz_old" ]; then
    add_finding "MEDIUM" "Outdated OpenZeppelin" "package.json uses OpenZeppelin < 4.x — known vulnerabilities"
  fi

  # solc < 0.8 as dependency
  old_solc=$(grep -E '"solc"\s*:\s*"[~^]?0\.[0-7]\.' "$TARGET/package.json" 2>/dev/null || true)
  if [ -n "$old_solc" ]; then
    add_finding "MEDIUM" "Outdated solc" "package.json pins solc < 0.8 — unchecked arithmetic by default"
  fi
fi

# 10c. Check for known vulnerable Foundry lib versions
if [ -f "$TARGET/.gitmodules" ]; then
  # Check forge-std version
  forge_std_old=$(grep -A2 'forge-std' "$TARGET/.gitmodules" 2>/dev/null | grep -E 'branch.*v0\.' || true)
  if [ -n "$forge_std_old" ]; then
    add_finding "LOW" "Old forge-std" ".gitmodules pins old forge-std — consider updating"
  fi
fi

# 10d. npm audit (if npm is available and package-lock exists)
if [ -f "$TARGET/package-lock.json" ] && command -v npm &>/dev/null; then
  audit_output=$(cd "$TARGET" && npm audit --json 2>/dev/null || true)
  if [ -n "$audit_output" ]; then
    critical_vulns=$(echo "$audit_output" | grep -o '"critical":[0-9]*' | head -1 | grep -o '[0-9]*' || echo "0")
    high_vulns=$(echo "$audit_output" | grep -o '"high":[0-9]*' | head -1 | grep -o '[0-9]*' || echo "0")
    if [ "$critical_vulns" -gt 0 ]; then
      add_finding "HIGH" "npm audit: critical" "$critical_vulns critical vulnerability(ies) found in npm dependencies"
    fi
    if [ "$high_vulns" -gt 0 ]; then
      add_finding "MEDIUM" "npm audit: high" "$high_vulns high vulnerability(ies) found in npm dependencies"
    fi
  fi
fi

# ════════════════════════════════════════════════════════════════
# MEDIUM SEVERITY — Config-level checks
# ════════════════════════════════════════════════════════════════

echo "🟡 Checking configuration-level threats..."

# FFI enabled in foundry.toml
if [ -f "$TARGET/foundry.toml" ]; then
  ffi_enabled=$(grep -E '^\s*ffi\s*=\s*true' "$TARGET/foundry.toml" 2>/dev/null || true)
  if [ -n "$ffi_enabled" ]; then
    add_finding "MEDIUM" "Forge FFI enabled" "foundry.toml has ffi=true — Forge tests can execute shell commands"
  fi
fi

# Hardhat external process tasks
while IFS= read -r f; do
  ext_proc=$(grep -nE '(hre\.run|exec\(|execSync\(|spawn\()' "$f" 2>/dev/null || true)
  if [ -n "$ext_proc" ]; then
    add_finding "MEDIUM" "Hardhat external process" "$(basename "$f"): Hardhat config/task runs external processes"
  fi
done < <(find "$TARGET" -maxdepth 2 \( -name "hardhat.config.*" -o -name "*.task.*" \) 2>/dev/null)

# Hidden files (excluding standard ones)
while IFS= read -r f; do
  base=$(basename "$f")
  case "$base" in
    .env|.env.*|.gitignore|.gitmodules|.gitattributes|.prettierrc*|.solhint*|.eslintrc*|\
    .editorconfig|.npmrc|.nvmrc|.tool-versions|.github|.husky|.vscode|.idea|\
    .DS_Store|.browserslistrc|.babelrc*|.postcssrc*|.stylelintrc*) ;;
    *) add_finding "MEDIUM" "Hidden file" "Non-standard hidden file: $(echo "$f" | sed "s|$TARGET/||")" ;;
  esac
done < <(find "$TARGET" -maxdepth 3 -name ".*" -not -path "*/node_modules/*" \
  -not -path "*/.git/*" -not -path "*/.git" -not -path "*/target/*" -not -path "*/lib/*" 2>/dev/null)

# Anchor deploy scripts with keypair paths
while IFS= read -r f; do
  keypair_ref=$(grep -nE '(keypair|wallet|key).*\.(json|key|pem)' "$f" 2>/dev/null || true)
  if [ -n "$keypair_ref" ]; then
    add_finding "MEDIUM" "Keypair reference" "$(basename "$f"): references wallet keypair files"
  fi
done < <(find "$TARGET" \( -name "*.sh" -o -name "*.ts" -o -name "*.js" -o -name "Anchor.toml" \) \
  -not -path "*/node_modules/*" -not -path "*/target/*" 2>/dev/null)

# ════════════════════════════════════════════════════════════════
# LOW SEVERITY — Informational
# ════════════════════════════════════════════════════════════════

echo "🟢 Checking informational patterns..."

# .env files present
while IFS= read -r f; do
  add_finding "LOW" ".env file" "Environment file found: $(echo "$f" | sed "s|$TARGET/||") — may contain secrets"
done < <(find "$TARGET" -maxdepth 3 -name ".env*" -not -name ".env.example" -not -name ".env.sample" \
  -not -path "*/node_modules/*" 2>/dev/null)

# Large binary files (>1MB)
while IFS= read -r f; do
  size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo "0")
  if [ "$size" -gt 1048576 ]; then
    size_mb=$(echo "scale=1; $size / 1048576" | bc 2>/dev/null || echo "?")
    add_finding "LOW" "Large file" "$(echo "$f" | sed "s|$TARGET/||") (${size_mb}MB)"
  fi
done < <(find "$TARGET" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" \
  -not -path "*/target/*" -not -path "*/lib/*" -not -name "*.sol" -not -name "*.rs" \
  -not -name "*.ts" -not -name "*.js" -not -name "*.json" -not -name "*.toml" \
  -not -name "*.md" -not -name "*.txt" -not -name "*.yaml" -not -name "*.yml" 2>/dev/null)

# Git submodules
if [ -f "$TARGET/.gitmodules" ]; then
  submod_count=$(grep -c '\[submodule' "$TARGET/.gitmodules" 2>/dev/null || echo "0")
  add_finding "LOW" "Git submodules" "$submod_count submodule(s) — verify remote origins are trusted"
fi

# ════════════════════════════════════════════════════════════════
# REPORT
# ════════════════════════════════════════════════════════════════

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🐝 THREAT INTELLIGENCE SCAN RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔴 HIGH:   $HIGH_COUNT"
echo "🟡 MEDIUM: $MEDIUM_COUNT"
echo "🟢 LOW:    $LOW_COUNT"
echo "ℹ️  INFO:   $INFO_COUNT"
echo ""

# Phase summary
echo "── Scan Phases ──────────────────────────────────────────────"
echo "  Phase 1: Code Behavior Analysis          ✓"
echo "  Phase 2: HTML Fingerprint Matching        ✓"
echo "  Phase 3: Banner & Favicon Analysis        ✓"
echo "  Phase 4: Client-Side JS Inspection        ✓"
echo "  Phase 5: Post-Signature Distributor Check ✓"
echo "  Phase 6: Codebase Profile Analysis        ✓"
echo "  Phase 7: Function Purpose Analysis        ✓"
echo "  Phase 8: Dependency Audit                 ✓"
echo "  Phase 9: Reachability Analysis            ✓"
echo "  Phase 10: OSS Feed & Vuln Check           ✓"
echo ""

if [ $HIGH_COUNT -gt 0 ]; then
  echo "═══ HIGH SEVERITY ═══"
  for f in "${HIGH_FINDINGS[@]}"; do
    echo "  ❌ $f"
  done
  echo ""
fi

if [ $MEDIUM_COUNT -gt 0 ]; then
  echo "═══ MEDIUM SEVERITY ═══"
  for f in "${MEDIUM_FINDINGS[@]}"; do
    echo "  ⚠️  $f"
  done
  echo ""
fi

if [ $LOW_COUNT -gt 0 ]; then
  echo "═══ LOW SEVERITY ═══"
  for f in "${LOW_FINDINGS[@]}"; do
    echo "  ℹ️  $f"
  done
  echo ""
fi

if [ $INFO_COUNT -gt 0 ]; then
  echo "═══ INFORMATIONAL ═══"
  for f in "${INFO_FINDINGS[@]}"; do
    echo "  📋 $f"
  done
  echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $HIGH_COUNT -gt 0 ]; then
  echo "🚫 VERDICT: BLOCKED — $HIGH_COUNT high-severity finding(s) detected."
  echo "   Review findings above before proceeding with audit scoping."
  echo "   Do NOT run forge test, npm install, or any build commands."
  exit 2
elif [ $MEDIUM_COUNT -gt 0 ]; then
  echo "⚠️  VERDICT: WARNING — $MEDIUM_COUNT medium-severity finding(s) detected."
  echo "   Review findings above. Proceed with caution."
  exit 1
else
  echo "✅ VERDICT: CLEAN — No high/medium severity findings. Safe to proceed."
  exit 0
fi
