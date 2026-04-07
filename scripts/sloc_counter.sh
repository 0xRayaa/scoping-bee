#!/usr/bin/env bash
# sloc_counter.sh — Count non-blank, non-comment source lines (nSLOC)
# Supports Solidity (.sol) and Rust (.rs) files
#
# Usage:
#   bash sloc_counter.sh <file_or_directory> [OPTIONS]
#
# Options:
#   --lang <solidity|rust|auto>    Language (default: auto-detect)
#   --include-tests                Count test files too
#   --include-interfaces           Count interface-only files (Solidity)
#   --pace <N>                     Auditor pace in nSLOC/day (default: 350)
#
# Examples:
#   bash sloc_counter.sh ./src                          # Auto-detect, 350 LOC/day
#   bash sloc_counter.sh ./programs --lang rust         # Force Rust mode
#   bash sloc_counter.sh ./src --pace 300               # Use 300 LOC/day estimate

set -euo pipefail

TARGET="${1:-.}"
LANG_MODE="auto"
INCLUDE_TESTS=false
INCLUDE_INTERFACES=false
AUDIT_PACE=350

# Parse options
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --lang) LANG_MODE="$2"; shift 2 ;;
    --include-tests) INCLUDE_TESTS=true; shift ;;
    --include-interfaces) INCLUDE_INTERFACES=true; shift ;;
    --pace) AUDIT_PACE="$2"; shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

# Auto-detect language
if [ "$LANG_MODE" = "auto" ]; then
  sol_count=$(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null | wc -l | tr -d '[:space:]')
  rs_count=$(find "$TARGET" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d '[:space:]')
  if [ "$sol_count" -gt "$rs_count" ]; then
    LANG_MODE="solidity"
  elif [ "$rs_count" -gt 0 ]; then
    LANG_MODE="rust"
  else
    LANG_MODE="solidity"  # Default
  fi
fi

count_nsloc_solidity() {
  local file="$1"
  perl -0777 -pe 's{/\*.*?\*/}{}gs' "$file" | \
    sed -E '
      /^\s*\/\//d
      s/\/\/.*$//
      /^\s*$/d
      /^\s*[\{\}]\s*$/d
      /^\s*(pragma|import|\/\/\s*SPDX)/d
    ' | wc -l | tr -d '[:space:]'
}

count_nsloc_rust() {
  local file="$1"
  perl -0777 -pe 's{/\*.*?\*/}{}gs' "$file" | \
    sed -E '
      /^\s*\/\//d
      s/\/\/.*$//
      /^\s*$/d
      /^\s*[\{\}]\s*$/d
      /^\s*(use |mod |pub use |pub mod )/d
      /^\s*#\[/d
      /^\s*#!\[/d
    ' | wc -l | tr -d '[:space:]'
}

# Collect files
FILES=()
if [ -f "$TARGET" ]; then
  FILES=("$TARGET")
else
  if [ "$LANG_MODE" = "solidity" ]; then
    EXT="*.sol"
    EXCLUDES=(-not -path "*/node_modules/*" -not -path "*/lib/*")
    if [ "$INCLUDE_TESTS" = false ]; then
      EXCLUDES+=(-not -path "*/test/*" -not -path "*/tests/*" -not -path "*/mock/*" -not -path "*/mocks/*" -not -path "*/script/*" -not -path "*/scripts/*")
    fi
  else
    EXT="*.rs"
    EXCLUDES=(-not -path "*/target/*")
    if [ "$INCLUDE_TESTS" = false ]; then
      EXCLUDES+=(-not -path "*/tests/*" -not -path "*/test/*" -not -name "*_test.rs")
    fi
  fi
  while IFS= read -r f; do
    FILES+=("$f")
  done < <(find "$TARGET" -name "$EXT" "${EXCLUDES[@]}" 2>/dev/null | sort)
fi

if [ ${#FILES[@]} -eq 0 ]; then
  echo "No source files found in: $TARGET (mode: $LANG_MODE)"
  exit 0
fi

TOTAL_NSLOC=0
TOTAL_FILES=0

echo "🐝 Scoping Bee — nSLOC Counter"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Language: $LANG_MODE | Audit pace: $AUDIT_PACE nSLOC/day"
echo ""
printf "%-60s %8s\n" "File" "nSLOC"
printf "%-60s %8s\n" "------------------------------------------------------------" "--------"

for file in "${FILES[@]}"; do
  # Skip interface-only Solidity files if flag not set
  if [ "$LANG_MODE" = "solidity" ] && [ "$INCLUDE_INTERFACES" = false ]; then
    is_interface=$(head -30 "$file" | grep -cE '^\s*(interface|abstract contract)\s+' 2>/dev/null || true)
    has_impl=$(grep -cE '^\s*function\s+\w+.*\{' "$file" 2>/dev/null || true)
    if [ "$is_interface" -gt 0 ] && [ "$has_impl" -lt 2 ]; then
      continue
    fi
  fi

  # Skip Rust mod.rs and lib.rs (re-export only)
  if [ "$LANG_MODE" = "rust" ]; then
    base=$(basename "$file")
    if [ "$base" = "mod.rs" ] || [ "$base" = "lib.rs" ]; then
      total_lines=$(wc -l < "$file" | tr -d '[:space:]')
      if [ "$total_lines" -lt 20 ]; then
        continue  # Skip tiny re-export files
      fi
    fi
  fi

  if [ "$LANG_MODE" = "solidity" ]; then
    nsloc=$(count_nsloc_solidity "$file")
  else
    nsloc=$(count_nsloc_rust "$file")
  fi

  rel_path="${file#$TARGET/}"
  if [ "$rel_path" = "$file" ]; then
    rel_path=$(basename "$file")
  fi

  printf "%-60s %8s\n" "$rel_path" "$nsloc"
  TOTAL_NSLOC=$((TOTAL_NSLOC + nsloc))
  TOTAL_FILES=$((TOTAL_FILES + 1))
done

printf "%-60s %8s\n" "------------------------------------------------------------" "--------"
printf "%-60s %8s\n" "TOTAL ($TOTAL_FILES files)" "$TOTAL_NSLOC"

# Effort estimation
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 EFFORT ESTIMATION"
echo ""

if [ "$TOTAL_NSLOC" -le 200 ]; then
  echo "   Complexity: SMALL (0–200 nSLOC)"
elif [ "$TOTAL_NSLOC" -le 500 ]; then
  echo "   Complexity: MEDIUM (201–500 nSLOC)"
elif [ "$TOTAL_NSLOC" -le 1000 ]; then
  echo "   Complexity: LARGE (501–1000 nSLOC)"
else
  echo "   Complexity: VERY LARGE (1000+ nSLOC)"
fi

# Calculate days (integer division, round up)
AUDIT_DAYS=$(( (TOTAL_NSLOC + AUDIT_PACE - 1) / AUDIT_PACE ))

echo "   Audit pace: $AUDIT_PACE nSLOC/day"
echo "   Estimated:  ~$AUDIT_DAYS day(s) ($TOTAL_NSLOC ÷ $AUDIT_PACE)"
echo ""
echo "   ⚡ Adjust pace with --pace <N> to recalculate"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
