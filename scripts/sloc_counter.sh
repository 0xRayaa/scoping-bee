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
  vy_count=$(find "$TARGET" -name "*.vy" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d '[:space:]')
  rs_count=$(find "$TARGET" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d '[:space:]')
  evm_count=$((sol_count + vy_count))
  if [ "$evm_count" -gt "$rs_count" ]; then
    LANG_MODE="solidity"
  elif [ "$rs_count" -gt 0 ]; then
    LANG_MODE="rust"
  else
    LANG_MODE="solidity"  # Default
  fi
fi

# Count total lines in a file
count_total_lines() {
  wc -l < "$1" | tr -d '[:space:]'
}

# Count comment lines — handles // and /* */ without double-counting
count_comment_lines() {
  local file="$1"
  perl -ne '
    BEGIN { $count = 0; $in_block = 0; }
    if ($in_block) {
      $count++;
      if (m{\*/}) { $in_block = 0; }
      next;
    }
    if (m{^\s*/\*}) {
      $count++;
      if (!m{\*/}) { $in_block = 1; }
      next;
    }
    if (m{^\s*//}) {
      $count++;
      next;
    }
    END { print $count; }
  ' "$file"
}

# Strip comments safely — avoids stripping // inside string literals
strip_comments() {
  local file="$1"
  perl -0777 -pe '
    # Remove block comments
    s{/\*.*?\*/}{}gs;
    # Remove single-line comments, but not // inside double-quoted strings
    s{
      (\"(?:[^\"\\\\]|\\\\.)*\")   # double-quoted string — preserve
      |
      (//[^\n]*)                    # single-line comment — remove
    }{
      defined($1) ? $1 : ""
    }gex;
  ' "$file"
}

# SLOC: non-blank, non-comment source lines
count_sloc_solidity() {
  local file="$1"
  strip_comments "$file" | \
    sed -E '/^\s*$/d' | wc -l | tr -d '[:space:]'
}

# nSLOC: counts ONLY logic lines inside function/modifier/constructor bodies
# Excludes: state vars, constants, struct/enum/event/error declarations,
#           imports, pragmas, contract declarations, function signatures, braces
count_nsloc_solidity() {
  local file="$1"
  strip_comments "$file" | perl -ne '
    BEGIN { $depth = 0; $in_body = 0; $body_depth = -1; $count = 0; $awaiting_brace = 0; }

    chomp;
    my $line = $_;

    # Skip blank lines everywhere
    next if $line =~ /^\s*$/;

    # Remove string contents (double-quoted and hex strings) for accurate brace counting
    (my $clean = $line) =~ s/hex"[^"]*"//g;
    $clean =~ s/"(?:[^"\\\\]|\\\\.)*"//g;

    my $opens = ($clean =~ tr/{//);
    my $closes = ($clean =~ tr/}//);

    # Detect function/modifier/constructor/receive/fallback declaration
    if (!$in_body && $line =~ /^\s*(function\s|modifier\s|constructor\s*\(|receive\s*\(|fallback\s*\()/) {
      $awaiting_brace = 1;
    }

    # Found the opening brace of the body
    if ($awaiting_brace && $opens > 0) {
      $in_body = 1;
      $awaiting_brace = 0;
      $body_depth = $depth + 1;
    }

    $depth += $opens - $closes;

    # Count lines inside function/modifier bodies only
    if ($in_body && $depth >= $body_depth) {
      # Skip brace/punctuation-only lines
      next if $line =~ /^\s*[\{\}\(\)\];,]+\s*$/;
      # Skip function/modifier/constructor signature lines
      next if $line =~ /^\s*(function\s|modifier\s|constructor\s*\(|receive\s*\(|fallback\s*\()/;
      # Skip closing paren of multi-line signatures
      next if $line =~ /^\s*\)\s*(external|public|internal|private|view|pure|payable|override|virtual|returns|nonReentrant|whenNotPaused|onlyOwner|onlyTradingModule|onlyRegisteredManager)*[\s{]*$/;
      # Skip lines that are only modifier/visibility keywords
      next if $line =~ /^\s*(external|public|internal|private|view|pure|payable|override|virtual|returns\s*\(.*\))\s*[\{]?\s*$/;
      $count++;
    }

    # Exited function body
    if ($in_body && $depth < $body_depth) {
      $in_body = 0;
      $body_depth = -1;
    }

    END { print $count; }
  '
}

count_sloc_rust() {
  local file="$1"
  strip_comments "$file" | \
    sed -E '/^\s*$/d' | wc -l | tr -d '[:space:]'
}

# nSLOC for Rust: counts only logic lines inside fn/impl bodies
# Excludes: use/mod, attributes, struct/enum field declarations, trait signatures
count_nsloc_rust() {
  local file="$1"
  strip_comments "$file" | perl -ne '
    BEGIN { $depth = 0; $in_body = 0; $body_depth = -1; $count = 0; $awaiting_brace = 0; }

    chomp;
    my $line = $_;
    next if $line =~ /^\s*$/;

    (my $clean = $line) =~ s/"(?:[^"\\\\]|\\\\.)*"//g;
    my $opens = ($clean =~ tr/{//);
    my $closes = ($clean =~ tr/}//);

    # Detect fn/impl block start
    if (!$in_body && $line =~ /^\s*(pub\s+)?(pub\(crate\)\s+)?(fn\s|impl\s)/) {
      $awaiting_brace = 1;
    }

    if ($awaiting_brace && $opens > 0) {
      $in_body = 1;
      $awaiting_brace = 0;
      $body_depth = $depth + 1;
    }

    $depth += $opens - $closes;

    if ($in_body && $depth >= $body_depth) {
      next if $line =~ /^\s*[\{\}\(\)\];,]+\s*$/;
      next if $line =~ /^\s*(pub\s+)?(pub\(crate\)\s+)?(fn\s|impl\s)/;
      next if $line =~ /^\s*(use |mod |pub use |pub mod |pub\(crate\) (use|mod) )/;
      next if $line =~ /^\s*#[\[!]/;
      next if $line =~ /^\s*extern\s+crate\s/;
      $count++;
    }

    if ($in_body && $depth < $body_depth) {
      $in_body = 0;
      $body_depth = -1;
    }

    END { print $count; }
  '
}

# Collect files
FILES=()
if [ -f "$TARGET" ]; then
  FILES=("$TARGET")
else
  if [ "$LANG_MODE" = "solidity" ]; then
    EXT="*.sol"
    EXT2="*.vy"
    EXCLUDES=(-not -path "*/node_modules/*" -not -path "*/lib/*")
    if [ "$INCLUDE_TESTS" = false ]; then
      EXCLUDES+=(-not -path "*/test/*" -not -path "*/tests/*" -not -path "*/mock/*" -not -path "*/mocks/*" -not -path "*/script/*" -not -path "*/scripts/*" -not -name "Mock*" -not -name "mock*" -not -name "*Mock.sol" -not -name "*mock.sol")
    fi
  else
    EXT="*.rs"
    EXCLUDES=(-not -path "*/target/*")
    if [ "$INCLUDE_TESTS" = false ]; then
      EXCLUDES+=(-not -path "*/tests/*" -not -path "*/test/*" -not -name "*_test.rs" -not -path "*/mock/*" -not -path "*/mocks/*" -not -name "mock_*" -not -name "*_mock.rs")
    fi
  fi
  while IFS= read -r f; do
    FILES+=("$f")
  done < <(find "$TARGET" \( -name "$EXT" ${EXT2:+-o -name "$EXT2"} \) "${EXCLUDES[@]}" 2>/dev/null | sort)
fi

if [ ${#FILES[@]} -eq 0 ]; then
  echo "No source files found in: $TARGET (mode: $LANG_MODE)"
  exit 0
fi

TOTAL_SLOC=0
TOTAL_NSLOC=0
TOTAL_LINES=0
TOTAL_COMMENT_LINES=0
TOTAL_FILES=0

echo "🐝 Scoping Bee — nSLOC Counter"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Language: $LANG_MODE | Audit pace: $AUDIT_PACE nSLOC/day"
echo ""
printf "%-55s %8s %8s %8s\n" "File" "Lines" "SLOC" "nSLOC"
printf "%-55s %8s %8s %8s\n" "-------------------------------------------------------" "--------" "--------" "--------"

for file in "${FILES[@]}"; do
  # Skip interface-only Solidity files if flag not set
  if [ "$LANG_MODE" = "solidity" ] && [ "$INCLUDE_INTERFACES" = false ]; then
    is_interface=$(grep -cE '^\s*(interface|abstract contract)\s+' "$file" 2>/dev/null || true)
    has_impl=$(grep -cE '^\s*function\s+\w+[^;]*\{' "$file" 2>/dev/null || true)
    if [ "$is_interface" -gt 0 ] && [ "$has_impl" -lt 2 ]; then
      continue
    fi
  fi

  # Skip Rust mod.rs and lib.rs (re-export only)
  if [ "$LANG_MODE" = "rust" ]; then
    base=$(basename "$file")
    if [ "$base" = "mod.rs" ] || [ "$base" = "lib.rs" ]; then
      file_total_lines=$(wc -l < "$file" | tr -d '[:space:]')
      if [ "$file_total_lines" -lt 20 ]; then
        continue  # Skip tiny re-export files
      fi
    fi
  fi

  total_lines=$(count_total_lines "$file")
  comment_lines=$(count_comment_lines "$file")

  if [ "$LANG_MODE" = "solidity" ]; then
    sloc=$(count_sloc_solidity "$file")
    nsloc=$(count_nsloc_solidity "$file")
  else
    sloc=$(count_sloc_rust "$file")
    nsloc=$(count_nsloc_rust "$file")
  fi

  rel_path="${file#$TARGET/}"
  if [ "$rel_path" = "$file" ]; then
    rel_path=$(basename "$file")
  fi

  printf "%-55s %8s %8s %8s\n" "$rel_path" "$total_lines" "$sloc" "$nsloc"
  TOTAL_LINES=$((TOTAL_LINES + total_lines))
  TOTAL_SLOC=$((TOTAL_SLOC + sloc))
  TOTAL_NSLOC=$((TOTAL_NSLOC + nsloc))
  TOTAL_COMMENT_LINES=$((TOTAL_COMMENT_LINES + comment_lines))
  TOTAL_FILES=$((TOTAL_FILES + 1))
done

printf "%-55s %8s %8s %8s\n" "-------------------------------------------------------" "--------" "--------" "--------"
printf "%-55s %8s %8s %8s\n" "TOTAL ($TOTAL_FILES files)" "$TOTAL_LINES" "$TOTAL_SLOC" "$TOTAL_NSLOC"

# Comment-to-source ratio
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📈 CODE METRICS"
echo ""
if [ "${TOTAL_SLOC:-0}" -gt 0 ]; then
  COMMENT_RATIO=$(awk "BEGIN {printf \"%.2f\", ${TOTAL_COMMENT_LINES:-0} / ${TOTAL_SLOC:-1}}")
  echo "   Total lines:            $TOTAL_LINES"
  echo "   Source lines (SLOC):    $TOTAL_SLOC"
  echo "   Normalized (nSLOC):     $TOTAL_NSLOC"
  echo "   Comment lines:          $TOTAL_COMMENT_LINES"
  echo "   Comment-to-source:      $COMMENT_RATIO"
else
  echo "   No source lines found."
fi

# Effort estimation
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 EFFORT ESTIMATION"
echo ""

if [ "$TOTAL_NSLOC" -le 200 ]; then
  echo "   Complexity: SMALL (0-200 nSLOC)"
elif [ "$TOTAL_NSLOC" -le 500 ]; then
  echo "   Complexity: MEDIUM (201-500 nSLOC)"
elif [ "$TOTAL_NSLOC" -le 1000 ]; then
  echo "   Complexity: LARGE (501-1000 nSLOC)"
else
  echo "   Complexity: VERY LARGE (1000+ nSLOC)"
fi

# Calculate days (integer division, round up)
if [ "$TOTAL_NSLOC" -gt 0 ]; then
  AUDIT_DAYS=$(( (TOTAL_NSLOC + AUDIT_PACE - 1) / AUDIT_PACE ))
else
  AUDIT_DAYS=0
fi

echo "   Audit pace: $AUDIT_PACE nSLOC/day"
echo "   Estimated:  ~$AUDIT_DAYS day(s) ($TOTAL_NSLOC / $AUDIT_PACE)"
echo ""
echo "   Adjust pace with --pace <N> to recalculate"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
