#!/usr/bin/env bash
# source_fetcher.sh — Fetch audit source code from multiple input types
#
# Usage:
#   bash source_fetcher.sh <input> [OPTIONS]
#
# Input types (auto-detected):
#   1. GitHub URL    → git clone (shallow)
#   2. Explorer URL or address  → fetch verified source via block explorer API
#   3. ZIP file path → extract locally
#   4. Local directory → use as-is (just validates it exists)
#
# Options:
#   --output <dir>        Output directory (default: ./audit-target)
#   --chain <chain>       Chain hint for address input (default: auto-detect from URL)
#   --api-key <key>       Block explorer API key (or set EXPLORER_API_KEY env var)
#   --branch <branch>     Git branch to clone (default: main)
#
# Supported explorers:
#   etherscan.io, goerli.etherscan.io, sepolia.etherscan.io
#   bscscan.com, testnet.bscscan.com
#   polygonscan.com, arbiscan.io, ftmscan.com, snowtrace.io
#   basescan.org, optimistic.etherscan.io
#
# Examples:
#   bash source_fetcher.sh https://github.com/org/repo
#   bash source_fetcher.sh 0x1234...abcd --chain bsc
#   bash source_fetcher.sh https://bscscan.com/address/0x1234...abcd
#   bash source_fetcher.sh ./audit-files.zip
#   bash source_fetcher.sh ./existing-directory

set -euo pipefail
export LC_ALL=C

# Dependency check
for cmd in git curl python3 unzip; do
  command -v "$cmd" &>/dev/null || { echo "❌ Required tool not found: $cmd"; exit 1; }
done

INPUT="${1:-}"
OUTPUT_DIR="./audit-target"
CHAIN=""
API_KEY="${EXPLORER_API_KEY:-}"
GIT_BRANCH="main"

if [ -z "$INPUT" ]; then
  echo "❌ Usage: bash source_fetcher.sh <github-url|explorer-url|address|zip-path|dir-path> [OPTIONS]"
  exit 1
fi

# Parse options
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --output|--chain|--api-key|--branch)
      if [ $# -lt 2 ]; then
        echo "❌ Option $1 requires a value"
        exit 1
      fi
      ;;
    esac
  case "$1" in
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --chain) CHAIN="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --branch) GIT_BRANCH="$2"; shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

echo "🐝 Scoping Bee — Source Fetcher"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Input: $INPUT"
echo ""

# ════════════════════════════════════════════════════════════════
# INPUT TYPE DETECTION
# ════════════════════════════════════════════════════════════════

detect_input_type() {
  local input="$1"

  # GitHub URL
  if echo "$input" | grep -qE '^https?://(www\.)?github\.com/'; then
    echo "github"
    return
  fi

  # Block explorer URL (contains address in path)
  if echo "$input" | grep -qE '(etherscan\.io|bscscan\.com|polygonscan\.com|arbiscan\.io|ftmscan\.com|snowtrace\.io|basescan\.org)'; then
    echo "explorer_url"
    return
  fi

  # Raw Ethereum address (0x + 40 hex chars)
  if echo "$input" | grep -qE '^0x[0-9a-fA-F]{40}$'; then
    echo "address"
    return
  fi

  # Archive file (ZIP, tar.gz, tgz, tar.bz2, tar.xz)
  if [ -f "$input" ] && echo "$input" | grep -qiE '\.(zip|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz)$'; then
    echo "archive"
    return
  fi

  # Local directory
  if [ -d "$input" ]; then
    echo "directory"
    return
  fi

  # Archive that doesn't exist yet
  if echo "$input" | grep -qiE '\.(zip|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz)$'; then
    echo "❌ Archive file not found: $input" >&2
    exit 1
  fi

  echo "unknown"
}

INPUT_TYPE=$(detect_input_type "$INPUT")
echo "📋 Detected input type: $INPUT_TYPE"

# ════════════════════════════════════════════════════════════════
# EXPLORER API CONFIGURATION
# ════════════════════════════════════════════════════════════════

# Maps chain/domain → API endpoint
get_explorer_api() {
  local chain_or_domain="$1"
  case "$chain_or_domain" in
    eth|ethereum|etherscan.io|"")
      echo "https://api.etherscan.io/api" ;;
    goerli|goerli.etherscan.io)
      echo "https://api-goerli.etherscan.io/api" ;;
    sepolia|sepolia.etherscan.io)
      echo "https://api-sepolia.etherscan.io/api" ;;
    bsc|bscscan.com)
      echo "https://api.bscscan.com/api" ;;
    bsc-testnet|bsctest|testnet.bscscan.com)
      echo "https://api-testnet.bscscan.com/api" ;;
    polygon|matic|polygonscan.com)
      echo "https://api.polygonscan.com/api" ;;
    arbitrum|arb|arbiscan.io)
      echo "https://api.arbiscan.io/api" ;;
    optimism|op|optimistic.etherscan.io)
      echo "https://api-optimistic.etherscan.io/api" ;;
    fantom|ftm|ftmscan.com)
      echo "https://api.ftmscan.com/api" ;;
    avalanche|avax|snowtrace.io)
      echo "https://api.snowtrace.io/api" ;;
    base|basescan.org)
      echo "https://api.basescan.org/api" ;;
    *)
      echo ""
      ;;
  esac
}

# Extract domain from explorer URL
extract_explorer_domain() {
  echo "$1" | sed -E 's|^https?://([^/]+).*|\1|'
}

# Extract address from explorer URL
extract_address_from_url() {
  echo "$1" | grep -oE '0x[0-9a-fA-F]{40}' | head -1
}

# ════════════════════════════════════════════════════════════════
# FETCHERS
# ════════════════════════════════════════════════════════════════

fetch_github() {
  local url="$1"
  local dest="$2"
  local branch="$3"

  echo "📥 Cloning GitHub repository..."
  echo "   URL: $url"
  echo "   Branch: $branch"
  echo ""

  # Clean URL (remove trailing slashes, .git suffix handling)
  local clean_url
  clean_url=$(echo "$url" | sed 's|/$||; s|\.git$||')

  if [ -d "$dest" ]; then
    echo "   ⚠️  Output directory exists. Removing..."
    rm -rf "$dest"
  fi

  git clone --depth 1 --branch "$branch" "${clean_url}.git" "$dest" 2>&1 || {
    echo "   ⚠️  Branch '$branch' not found. Trying default branch..."
    rm -rf "$dest"
    git clone --depth 1 "$clean_url" "$dest" 2>&1
  }

  # Initialize git submodules (Foundry repos need lib/ populated)
  if [ -f "$dest/.gitmodules" ]; then
    echo "   📦 Initializing git submodules..."
    git -C "$dest" submodule update --init --recursive 2>&1 || {
      echo "   ⚠️  Submodule init failed (shallow clone). Trying full fetch..."
      git -C "$dest" fetch --unshallow 2>/dev/null || true
      git -C "$dest" submodule update --init --recursive 2>&1 || true
    }
  fi

  echo ""
  echo "   ✅ Cloned to: $dest"

  # Show basic stats
  local file_count
  file_count=$(find "$dest" -type f -not -path "*/.git/*" | wc -l | tr -d '[:space:]')
  echo "   📂 Files: $file_count"
}

fetch_explorer() {
  local address="$1"
  local chain="$2"
  local dest="$3"
  local api_key="$4"

  local api_url
  api_url=$(get_explorer_api "$chain")

  if [ -z "$api_url" ]; then
    echo "❌ Unsupported chain: $chain"
    echo "   Supported: eth, goerli, sepolia, bsc, bsc-testnet, polygon, arbitrum, optimism, fantom, avalanche, base"
    exit 1
  fi

  echo "📥 Fetching verified source from block explorer..."
  echo "   Address: $address"
  echo "   Chain: $chain"
  echo "   API: $api_url"
  echo ""

  # Build API URL
  local request_url="${api_url}?module=contract&action=getsourcecode&address=${address}"
  if [ -n "$api_key" ]; then
    request_url="${request_url}&apikey=${api_key}"
  fi

  # Fetch source code
  local response
  response=$(curl -s "$request_url")

  # Check for errors
  local status
  status=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','0'))" 2>/dev/null || echo "0")

  if [ "$status" != "1" ]; then
    local message
    message=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message','Unknown error'))" 2>/dev/null || echo "API error")
    echo "❌ Explorer API error: $message"
    echo ""
    echo "   Possible causes:"
    echo "   - Contract is not verified"
    echo "   - Invalid address"
    echo "   - API rate limit (provide --api-key)"
    echo "   - Wrong chain (use --chain <chain>)"
    exit 1
  fi

  # Create output directory
  mkdir -p "$dest"

  # Extract and write source files using Python
  # Pass response via stdin and variables via environment to prevent shell injection
  export FETCHER_DEST="$dest" FETCHER_ADDRESS="$address" FETCHER_CHAIN="$chain"
  echo "$response" | python3 -c '
import json, os, sys

response = json.load(sys.stdin)
result = response["result"][0]

contract_name = result.get("ContractName", "Unknown")
compiler = result.get("CompilerVersion", "Unknown")
optimization = result.get("OptimizationUsed", "0")
runs = result.get("Runs", "200")
evm_version = result.get("EVMVersion", "default")
proxy = result.get("Proxy", "0")
implementation = result.get("Implementation", "")

dest = os.environ["FETCHER_DEST"]
address = os.environ["FETCHER_ADDRESS"]
chain = os.environ["FETCHER_CHAIN"]

print(f"   Contract: {contract_name}")
print(f"   Compiler: {compiler}")
opt_str = "Yes" if optimization == "1" else "No"
print(f"   Optimization: {opt_str} ({runs} runs)")
if proxy == "1":
    print(f"   Warning: Proxy contract! Implementation: {implementation}")
print()

source = result.get("SourceCode", "")

if not source:
    print("Error: No source code found. Contract may not be verified.")
    sys.exit(1)

file_count = 0

# Handle multi-file source (JSON format)
# Etherscan wraps multi-file in double {{ }}
if source.startswith("{{"):
    source = source[1:-1]  # Remove outer braces

if source.startswith("{"):
    try:
        parsed = json.loads(source)
        # Standard JSON input format
        if "sources" in parsed:
            sources = parsed["sources"]
        else:
            sources = parsed

        for filepath, content in sources.items():
            if isinstance(content, dict):
                code = content.get("content", "")
            else:
                code = content

            # Clean up path — strip leading ./ prefix safely
            if filepath.startswith("./"):
                filepath = filepath[2:]

            full_path = os.path.join(dest, filepath)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            with open(full_path, "w") as f:
                f.write(code)
            file_count += 1
            print(f"   {filepath}")
    except json.JSONDecodeError:
        # Single file that starts with {
        full_path = os.path.join(dest, f"{contract_name}.sol")
        with open(full_path, "w") as f:
            f.write(source)
        file_count = 1
        print(f"   {contract_name}.sol")
else:
    # Single file source
    full_path = os.path.join(dest, f"{contract_name}.sol")
    with open(full_path, "w") as f:
        f.write(source)
    file_count = 1
    print(f"   {contract_name}.sol")

# Write metadata
meta = {
    "address": address,
    "chain": chain,
    "contract_name": contract_name,
    "compiler": compiler,
    "optimization": optimization == "1",
    "runs": int(runs),
    "evm_version": evm_version,
    "is_proxy": proxy == "1",
    "implementation": implementation,
    "abi_available": bool(result.get("ABI", ""))
}

with open(os.path.join(dest, ".explorer_metadata.json"), "w") as f:
    json.dump(meta, f, indent=2)

# Write ABI if available
abi = result.get("ABI", "")
if abi and abi != "Contract source code not verified":
    with open(os.path.join(dest, f"{contract_name}.abi.json"), "w") as f:
        f.write(abi)
    print(f"   {contract_name}.abi.json")

print()
print(f"   Extracted {file_count} source file(s) to: {dest}")
'
}

fetch_archive() {
  local archive_path="$1"
  local dest="$2"

  echo "📥 Extracting archive..."
  echo "   File: $archive_path"
  echo ""

  if [ -d "$dest" ]; then
    echo "   ⚠️  Output directory exists. Removing..."
    rm -rf "$dest"
  fi

  mkdir -p "$dest"

  # Detect archive type and extract
  local file_type
  file_type=$(file "$archive_path" 2>/dev/null || echo "")
  if echo "$file_type" | grep -qi 'zip'; then
    unzip -q "$archive_path" -d "$dest"
  elif echo "$file_type" | grep -qiE 'gzip|tar'; then
    tar -xf "$archive_path" -C "$dest"
  elif echo "$archive_path" | grep -qiE '\.(tar\.gz|tgz)$'; then
    tar -xzf "$archive_path" -C "$dest"
  elif echo "$archive_path" | grep -qiE '\.(tar\.bz2|tbz2)$'; then
    tar -xjf "$archive_path" -C "$dest"
  elif echo "$archive_path" | grep -qiE '\.tar\.xz$'; then
    tar -xJf "$archive_path" -C "$dest"
  elif echo "$archive_path" | grep -qiE '\.zip$'; then
    unzip -q "$archive_path" -d "$dest"
  else
    echo "❌ Unsupported archive format. Supported: .zip, .tar.gz, .tgz, .tar.bz2, .tar.xz"
    exit 1
  fi

  # If archive extracted into a single subdirectory, flatten it
  local contents
  contents=$(ls -1 "$dest" | wc -l | tr -d '[:space:]')
  if [ "$contents" = "1" ]; then
    local single_dir
    single_dir=$(ls -1 "$dest")
    if [ -d "$dest/$single_dir" ]; then
      echo "   📂 Flattening single root directory: $single_dir/"
      # Move contents up one level using find to avoid . and .. issues
      find "$dest/$single_dir" -maxdepth 1 -mindepth 1 -exec mv {} "$dest/" \;
      rmdir "$dest/$single_dir" 2>/dev/null || true
    fi
  fi

  local file_count
  file_count=$(find "$dest" -type f | wc -l | tr -d '[:space:]')
  echo "   ✅ Extracted to: $dest"
  echo "   📂 Files: $file_count"
}

use_directory() {
  local dir="$1"
  local dest="$2"

  echo "📂 Using local directory..."
  echo "   Path: $dir"
  echo ""

  # If input == output, just validate
  local abs_input abs_output
  abs_input=$(cd "$dir" && pwd)

  abs_output=$(cd "$dest" 2>/dev/null && pwd || realpath "$dest" 2>/dev/null || echo "$dest")
  if [ "$dir" = "$dest" ] || [ "$abs_input" = "$abs_output" ]; then
    echo "   ✅ Using in-place: $dir"
  else
    # Copy to output dir
    if [ -d "$dest" ]; then
      rm -rf "$dest"
    fi
    cp -r "$dir" "$dest"
    echo "   ✅ Copied to: $dest"
  fi

  local file_count
  file_count=$(find "$dest" -type f -not -path "*/.git/*" | wc -l | tr -d '[:space:]')
  echo "   📂 Files: $file_count"
}

# ════════════════════════════════════════════════════════════════
# EXECUTE
# ════════════════════════════════════════════════════════════════

case "$INPUT_TYPE" in
  github)
    fetch_github "$INPUT" "$OUTPUT_DIR" "$GIT_BRANCH"
    ;;
  explorer_url)
    DOMAIN=$(extract_explorer_domain "$INPUT")
    ADDRESS=$(extract_address_from_url "$INPUT")
    if [ -z "$ADDRESS" ]; then
      echo "❌ Could not extract contract address from URL: $INPUT"
      exit 1
    fi
    if [ -z "$CHAIN" ]; then
      CHAIN="$DOMAIN"
    fi
    fetch_explorer "$ADDRESS" "$CHAIN" "$OUTPUT_DIR" "$API_KEY"
    ;;
  address)
    if [ -z "$CHAIN" ]; then
      echo "⚠️  No chain specified for raw address. Defaulting to 'eth'."
      echo "   Use --chain <chain> to specify (eth, bsc, polygon, arbitrum, etc.)"
      echo ""
      CHAIN="eth"
    fi
    fetch_explorer "$INPUT" "$CHAIN" "$OUTPUT_DIR" "$API_KEY"
    ;;
  archive)
    fetch_archive "$INPUT" "$OUTPUT_DIR"
    ;;
  directory)
    use_directory "$INPUT" "$OUTPUT_DIR"
    ;;
  *)
    echo "❌ Could not determine input type for: $INPUT"
    echo ""
    echo "   Supported inputs:"
    echo "   • GitHub URL:      https://github.com/org/repo"
    echo "   • Explorer URL:    https://bscscan.com/address/0x..."
    echo "   • Contract address: 0x... (with --chain <chain>)"
    echo "   • ZIP file:        ./contracts.zip"
    echo "   • Local directory:  ./src"
    exit 1
    ;;
esac

# ════════════════════════════════════════════════════════════════
# POST-FETCH SUMMARY
# ════════════════════════════════════════════════════════════════

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🐝 SOURCE READY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "   Source type:  $INPUT_TYPE"
echo "   Output dir:   $OUTPUT_DIR"

# Detect what's in the directory
SOL_COUNT=$(find "$OUTPUT_DIR" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null | wc -l | tr -d '[:space:]')
RS_COUNT=$(find "$OUTPUT_DIR" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d '[:space:]')

if [ "$SOL_COUNT" -gt 0 ]; then
  echo "   Solidity files: $SOL_COUNT"
fi
if [ "$RS_COUNT" -gt 0 ]; then
  echo "   Rust files: $RS_COUNT"
fi

# Check for framework config
[ -f "$OUTPUT_DIR/foundry.toml" ] && echo "   Framework: Foundry"
{ [ -f "$OUTPUT_DIR/hardhat.config.js" ] || [ -f "$OUTPUT_DIR/hardhat.config.ts" ]; } && echo "   Framework: Hardhat"
[ -f "$OUTPUT_DIR/Anchor.toml" ] && echo "   Framework: Anchor (Solana)"
[ -f "$OUTPUT_DIR/Cargo.toml" ] && echo "   Cargo.toml found"

echo ""
echo "   ➡️  Ready for: bash scripts/threat_intel_scan.sh $OUTPUT_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
