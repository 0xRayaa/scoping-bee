#!/usr/bin/env bash
# codebase_visualizer.sh — Generate Mermaid diagrams for smart contract complexity analysis
#
# Usage:
#   bash codebase_visualizer.sh <project_root> [OPTIONS]
#
# Options:
#   --lang <solidity|rust|auto>    Language (default: auto-detect)
#   --output <file.md>             Output file (default: stdout)
#   --include-tests                Include test files in diagrams
#   --diagram <all|inheritance|calls|state|access|deps|flow>
#                                  Which diagrams to generate (default: all)
#
# Generates Mermaid-formatted diagrams:
#   1. Contract Inheritance Tree
#   2. Inter-Contract Call Graph
#   3. State Variable Dependency Map
#   4. Access Control Flow
#   5. External Dependency Graph
#   6. Function Flow (entry points → internal → external calls)
#
# Output is a Markdown file with embedded Mermaid blocks that can be
# rendered in GitHub, VS Code, or any Mermaid-compatible viewer.

set -euo pipefail

TARGET="${1:-.}"
LANG_MODE="auto"
OUTPUT=""
INCLUDE_TESTS=false
DIAGRAM_MODE="all"

# Parse options
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --lang) LANG_MODE="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --include-tests) INCLUDE_TESTS=true; shift ;;
    --diagram) DIAGRAM_MODE="$2"; shift 2 ;;
    *) echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [ ! -d "$TARGET" ]; then
  echo "❌ Directory not found: $TARGET"
  exit 1
fi

# Auto-detect language
if [ "$LANG_MODE" = "auto" ]; then
  sol_count=$(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null | wc -l | tr -d '[:space:]')
  rs_count=$(find "$TARGET" -name "*.rs" -not -path "*/target/*" 2>/dev/null | wc -l | tr -d '[:space:]')
  if [ "$sol_count" -gt "$rs_count" ]; then
    LANG_MODE="solidity"
  elif [ "$rs_count" -gt 0 ]; then
    LANG_MODE="rust"
  else
    LANG_MODE="solidity"
  fi
fi

# Collect source files
collect_files() {
  if [ "$LANG_MODE" = "solidity" ]; then
    local excludes=(-not -path "*/node_modules/*" -not -path "*/lib/*")
    if [ "$INCLUDE_TESTS" = false ]; then
      excludes+=(-not -path "*/test/*" -not -path "*/tests/*" -not -path "*/mock/*" -not -path "*/mocks/*")
    fi
    find "$TARGET" -name "*.sol" "${excludes[@]}" 2>/dev/null | sort
  else
    local excludes=(-not -path "*/target/*")
    if [ "$INCLUDE_TESTS" = false ]; then
      excludes+=(-not -path "*/tests/*" -not -name "*_test.rs")
    fi
    find "$TARGET" -name "*.rs" "${excludes[@]}" 2>/dev/null | sort
  fi
}

FILES=()
while IFS= read -r f; do
  FILES+=("$f")
done < <(collect_files)

if [ ${#FILES[@]} -eq 0 ]; then
  echo "No source files found in: $TARGET (mode: $LANG_MODE)"
  exit 0
fi

# ════════════════════════════════════════════════════════════════
# HELPER: Sanitize names for Mermaid (remove special chars)
# ════════════════════════════════════════════════════════════════

sanitize() {
  echo "$1" | sed 's/[^a-zA-Z0-9_]/_/g'
}

# ════════════════════════════════════════════════════════════════
# OUTPUT BUFFER
# ════════════════════════════════════════════════════════════════

BUFFER=""

emit() {
  BUFFER+="$1"$'\n'
}

flush() {
  if [ -n "$OUTPUT" ]; then
    echo "$BUFFER" > "$OUTPUT"
    echo "📄 Diagrams written to: $OUTPUT"
  else
    echo "$BUFFER"
  fi
}

# ════════════════════════════════════════════════════════════════
# ANALYSIS: Extract contract metadata
# ════════════════════════════════════════════════════════════════

# Arrays for collected data
declare -a CONTRACT_NAMES=()
declare -a CONTRACT_FILES=()
declare -a CONTRACT_TYPES=()  # contract, interface, abstract, library

extract_solidity_metadata() {
  for file in "${FILES[@]}"; do
    local rel_path="${file#$TARGET/}"

    # Extract contract/interface/library declarations
    while IFS= read -r line; do
      local ctype=$(echo "$line" | grep -oE '^\s*(contract|interface|abstract contract|library)' | sed 's/^[[:space:]]*//' || true)
      local cname=$(echo "$line" | sed -E 's/^[[:space:]]*(abstract[[:space:]]+)?(contract|interface|library)[[:space:]]+([A-Za-z0-9_]+).*/\3/' || true)

      if [ -n "$cname" ] && [ -n "$ctype" ]; then
        CONTRACT_NAMES+=("$cname")
        CONTRACT_FILES+=("$rel_path")
        # Normalize type
        case "$ctype" in
          "abstract contract") CONTRACT_TYPES+=("abstract") ;;
          *) CONTRACT_TYPES+=("$ctype") ;;
        esac
      fi
    done < <(grep -E '^\s*(contract|interface|abstract contract|library)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null || true)
  done
}

extract_rust_metadata() {
  for file in "${FILES[@]}"; do
    local rel_path="${file#$TARGET/}"

    # Extract struct/trait/impl/mod declarations (Anchor programs show as mod with #[program])
    while IFS= read -r line; do
      local cname=$(echo "$line" | sed -E 's/^[[:space:]]*(pub[[:space:]]+)?(struct|trait|impl|mod)[[:space:]]+([A-Za-z0-9_]+).*/\3/' || true)
      local ctype=$(echo "$line" | grep -oE '(struct|trait|impl|mod)' | head -1 || true)

      if [ -n "$cname" ] && [ -n "$ctype" ]; then
        CONTRACT_NAMES+=("$cname")
        CONTRACT_FILES+=("$rel_path")
        CONTRACT_TYPES+=("$ctype")
      fi
    done < <(grep -E '^\s*(pub\s+)?(struct|trait|impl|mod)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | \
      grep -v "^\s*//" | head -50 || true)
  done
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 1: INHERITANCE / TRAIT HIERARCHY
# ════════════════════════════════════════════════════════════════

generate_inheritance_diagram() {
  emit "## 1. Inheritance Hierarchy"
  emit ""
  emit "Shows contract inheritance (Solidity \`is\`) or trait implementations (Rust \`impl Trait for\`)."
  emit ""
  emit '```mermaid'
  emit "graph TD"

  local has_edges=false

  if [ "$LANG_MODE" = "solidity" ]; then
    # Style definitions
    emit "  classDef contract fill:#4a90d9,stroke:#2c5f8a,color:#fff"
    emit "  classDef interface fill:#7dc97d,stroke:#4a8a4a,color:#fff"
    emit "  classDef abstract fill:#d9a74a,stroke:#8a6a2c,color:#fff"
    emit "  classDef library fill:#9b7dd9,stroke:#5f4a8a,color:#fff"
    emit ""

    for file in "${FILES[@]}"; do
      # Extract: contract Foo is Bar, Baz
      while IFS= read -r line; do
        local child=$(echo "$line" | sed -E 's/^[[:space:]]*(abstract[[:space:]]+)?(contract|interface|library)[[:space:]]+([A-Za-z0-9_]+).*/\3/')
        local parents=$(echo "$line" | grep -oE 'is\s+[A-Za-z0-9_, ]+' | sed 's/^is[[:space:]]*//')

        if [ -n "$parents" ]; then
          IFS=',' read -ra PARENT_LIST <<< "$parents"
          for parent in "${PARENT_LIST[@]}"; do
            parent=$(echo "$parent" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            if [ -n "$parent" ]; then
              emit "  $(sanitize "$parent") --> $(sanitize "$child")"
              has_edges=true
            fi
          done
        fi
      done < <(grep -E '(contract|interface|library)\s+[A-Za-z0-9_]+\s+is\s+' "$file" 2>/dev/null || true)
    done

    # Add node styling
    for i in "${!CONTRACT_NAMES[@]}"; do
      local name="${CONTRACT_NAMES[$i]}"
      local type="${CONTRACT_TYPES[$i]}"
      local sid=$(sanitize "$name")
      case "$type" in
        contract) emit "  ${sid}[\"📄 ${name}\"]:::contract" ;;
        interface) emit "  ${sid}[\"🔗 ${name}\"]:::interface" ;;
        abstract) emit "  ${sid}[\"📋 ${name}\"]:::abstract" ;;
        library) emit "  ${sid}[\"📚 ${name}\"]:::library" ;;
      esac
    done

  else
    # Rust: impl Trait for Struct
    emit "  classDef struct_style fill:#4a90d9,stroke:#2c5f8a,color:#fff"
    emit "  classDef trait_style fill:#7dc97d,stroke:#4a8a4a,color:#fff"
    emit ""

    for file in "${FILES[@]}"; do
      while IFS= read -r line; do
        local trait_name=$(echo "$line" | sed -E 's/^[[:space:]]*impl[[:space:]]+([A-Za-z0-9_]+)[[:space:]]+for[[:space:]]+.*/\1/')
        local struct_name=$(echo "$line" | sed -E 's/.*for[[:space:]]+([A-Za-z0-9_]+).*/\1/')
        if [ -n "$trait_name" ] && [ -n "$struct_name" ] && [ "$trait_name" != "$struct_name" ]; then
          emit "  $(sanitize "$trait_name") -->|implements| $(sanitize "$struct_name")"
          has_edges=true
        fi
      done < <(grep -E '^\s*impl\s+[A-Za-z0-9_]+\s+for\s+[A-Za-z0-9_]+' "$file" 2>/dev/null || true)
    done
  fi

  if [ "$has_edges" = false ]; then
    emit "  NoInheritance[\"No inheritance relationships found\"]"
  fi

  emit '```'
  emit ""
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 2: INTER-CONTRACT CALL GRAPH
# ════════════════════════════════════════════════════════════════

generate_call_graph() {
  emit "## 2. Inter-Contract Call Graph"
  emit ""
  emit "Shows which contracts call functions on other contracts."
  emit ""
  emit '```mermaid'
  emit "graph LR"
  emit "  classDef caller fill:#4a90d9,stroke:#2c5f8a,color:#fff"
  emit "  classDef callee fill:#d94a4a,stroke:#8a2c2c,color:#fff"
  emit ""

  local has_edges=false
  local CALL_EDGES_SEEN=""

  if [ "$LANG_MODE" = "solidity" ]; then
    for file in "${FILES[@]}"; do
      # Get the contract name from this file
      local current_contract=$(grep -oE '(contract|library)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $2}' || true)
      [ -z "$current_contract" ] && continue

      # Find external contract calls: ISomeContract(addr).method() or contract.method()
      while IFS= read -r line; do
        local called=$(echo "$line" | grep -oE '[A-Z][A-Za-z0-9_]+\([^)]*\)\.[a-zA-Z]' | sed -E 's/\(.*//' || true)
        if [ -n "$called" ]; then
          local edge_key="${current_contract}->${called}"
          if ! echo "$CALL_EDGES_SEEN" | grep -qF "|${edge_key}|"; then
            CALL_EDGES_SEEN="${CALL_EDGES_SEEN}|${edge_key}|"
            emit "  $(sanitize "$current_contract") -->|calls| $(sanitize "$called")"
            has_edges=true
          fi
        fi
      done < <(grep -E '[A-Z][A-Za-z0-9_]+\([^)]*\)\.[a-zA-Z]' "$file" 2>/dev/null || true)

      # Also detect: IERC20(token).transfer, IUniswap, etc.
      while IFS= read -r iface; do
        local edge_key="${current_contract}->${iface}"
        if ! echo "$CALL_EDGES_SEEN" | grep -qF "|${edge_key}|"; then
          CALL_EDGES_SEEN="${CALL_EDGES_SEEN}|${edge_key}|"
          emit "  $(sanitize "$current_contract") -->|calls| $(sanitize "$iface")"
          has_edges=true
        fi
      done < <(grep -oE 'I[A-Z][A-Za-z0-9_]+\(' "$file" 2>/dev/null | sed 's/($//' | sort -u || true)

    done

  else
    # Rust: CPI invoke / invoke_signed calls
    for file in "${FILES[@]}"; do
      local current_mod=$(grep -oE '(pub\s+)?mod\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
      [ -z "$current_mod" ] && current_mod=$(basename "$file" .rs)

      while IFS= read -r line; do
        local target=$(echo "$line" | grep -oE '[a-z_]+::[a-z_]+' | head -1 | cut -d: -f1 || true)
        if [ -n "$target" ]; then
          local edge_key="${current_mod}->${target}"
          if ! echo "$CALL_EDGES_SEEN" | grep -qF "|${edge_key}|"; then
            CALL_EDGES_SEEN="${CALL_EDGES_SEEN}|${edge_key}|"
            emit "  $(sanitize "$current_mod") -->|CPI| $(sanitize "$target")"
            has_edges=true
          fi
        fi
      done < <(grep -E '(invoke|invoke_signed|CpiContext)' "$file" 2>/dev/null || true)
    done
  fi

  if [ "$has_edges" = false ]; then
    emit "  NoCalls[\"No inter-contract calls detected\"]"
  fi

  emit '```'
  emit ""
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 3: STATE VARIABLE DEPENDENCY MAP
# ════════════════════════════════════════════════════════════════

generate_state_diagram() {
  emit "## 3. State Variable Map"
  emit ""
  emit "State variables per contract with types and visibility."
  emit ""
  emit '```mermaid'
  emit "classDiagram"

  if [ "$LANG_MODE" = "solidity" ]; then
    for file in "${FILES[@]}"; do
      local current_contract=$(grep -oE '(contract|abstract contract)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
      [ -z "$current_contract" ] && continue

      local sid=$(sanitize "$current_contract")
      local has_state=false

      # Extract state variables (lines with mapping, uint, address, bool, bytes, etc. at contract level)
      while IFS= read -r line; do
        local var_info=$(echo "$line" | sed -E 's/^[[:space:]]+//' | sed -E 's/[[:space:]]*[=;].*//' | tr -s ' ')
        if [ -n "$var_info" ]; then
          # Escape special chars for Mermaid
          var_info=$(echo "$var_info" | sed 's/[<>]//g; s/"/\\"/g; s/=>/to/g')
          if [ "$has_state" = false ]; then
            emit "  class ${sid} {"
            has_state=true
          fi
          # Determine visibility
          if echo "$line" | grep -q "public"; then
            emit "    +${var_info}"
          elif echo "$line" | grep -q "private"; then
            emit "    -${var_info}"
          elif echo "$line" | grep -q "internal"; then
            emit "    #${var_info}"
          else
            emit "    #${var_info}"
          fi
        fi
      done < <(grep -E '^\s+(mapping|uint|int|address|bool|bytes|string|struct|enum|I[A-Z])[A-Za-z0-9_(\[\] =>)]+\s+(public|private|internal|immutable|constant)?' "$file" 2>/dev/null | \
        grep -v "function\|event\|error\|modifier\|return\|emit\|require\|assert" | head -30 || true)

      # Also extract functions as methods
      while IFS= read -r line; do
        local func_name=$(echo "$line" | sed -E 's/^[[:space:]]*function[[:space:]]+([A-Za-z0-9_]+).*/\1/')
        local visibility="+"
        echo "$line" | grep -q "internal" && visibility="#"
        echo "$line" | grep -q "private" && visibility="-"
        if [ "$has_state" = false ]; then
          emit "  class ${sid} {"
          has_state=true
        fi
        local returns=""
        returns=$(echo "$line" | grep -oE 'returns[[:space:]]*\([^)]*\)' | sed 's/returns[[:space:]]*(\(.*\))/\1/' || true)
        emit "    ${visibility}${func_name}()${returns:+ $returns}"
      done < <(grep -E '^\s*function\s+[a-zA-Z]' "$file" 2>/dev/null | head -25 || true)

      if [ "$has_state" = true ]; then
        emit "  }"
      else
        emit "  class ${sid}"
      fi
      emit ""
    done

  else
    # Rust: struct fields
    for file in "${FILES[@]}"; do
      local in_struct=false
      local struct_name=""
      local brace_depth=0

      while IFS= read -r line; do
        # Detect struct start
        if echo "$line" | grep -qE '^\s*(pub\s+)?struct\s+[A-Za-z0-9_]+'; then
          struct_name=$(echo "$line" | sed -E 's/^[[:space:]]*(pub[[:space:]]+)?struct[[:space:]]+([A-Za-z0-9_]+).*/\2/')
          in_struct=true
          emit "  class $(sanitize "$struct_name") {"
          continue
        fi

        if [ "$in_struct" = true ]; then
          # Check for closing brace
          if echo "$line" | grep -q '^}'; then
            in_struct=false
            emit "  }"
            emit ""
            continue
          fi

          # Extract field
          local field=$(echo "$line" | sed -E 's/^[[:space:]]*(pub[[:space:]]+)?([a-z_][a-z0-9_]*)[[:space:]]*:[[:space:]]*([^,]+).*/\2: \3/' | sed 's/,$//')
          if [ -n "$field" ] && [ "$field" != "$line" ]; then
            local vis="+"
            echo "$line" | grep -q "pub" || vis="#"
            field=$(echo "$field" | sed 's/[<>]//g; s/=>/to/g')
            emit "    ${vis}${field}"
          fi
        fi
      done < "$file"
    done
  fi

  emit '```'
  emit ""
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 4: ACCESS CONTROL FLOW
# ════════════════════════════════════════════════════════════════

generate_access_control_diagram() {
  emit "## 4. Access Control Flow"
  emit ""
  emit "Maps roles, modifiers, and protected functions."
  emit ""
  emit '```mermaid'
  emit "graph TD"
  emit "  classDef role fill:#d94a4a,stroke:#8a2c2c,color:#fff"
  emit "  classDef modifier fill:#d9a74a,stroke:#8a6a2c,color:#fff"
  emit "  classDef func fill:#4a90d9,stroke:#2c5f8a,color:#fff"
  emit ""

  local has_content=false

  if [ "$LANG_MODE" = "solidity" ]; then
    local MODIFIERS_LIST=""
    local ROLES_LIST=""

    for file in "${FILES[@]}"; do
      local current_contract=$(grep -oE '(contract|abstract contract)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
      [ -z "$current_contract" ] && continue

      # Extract modifiers defined in this contract
      while IFS= read -r mod_name; do
        if ! echo "$MODIFIERS_LIST" | grep -qF "|${mod_name}|"; then
          MODIFIERS_LIST="${MODIFIERS_LIST}|${mod_name}|"
          emit "  $(sanitize "mod_${mod_name}")[\"🔒 ${mod_name}\"]:::modifier"
          has_content=true
        fi
      done < <(grep -oE 'modifier\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | awk '{print $2}' || true)

      # Extract role-based patterns
      while IFS= read -r role; do
        role=$(echo "$role" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [ -n "$role" ] && ! echo "$ROLES_LIST" | grep -qF "|${role}|"; then
          ROLES_LIST="${ROLES_LIST}|${role}|"
          emit "  $(sanitize "role_${role}")[\"👤 ${role}\"]:::role"
          has_content=true
        fi
      done < <(grep -oE '(ADMIN|OWNER|MINTER|PAUSER|OPERATOR|MANAGER|GUARDIAN|KEEPER|GOVERNOR|DEFAULT_ADMIN)_ROLE' "$file" 2>/dev/null | sort -u || true)

      # Collect modifier names for this file
      local file_modifiers=$(grep -oE 'modifier\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | awk '{print $2}' | sort -u || true)

      # Link functions to their modifiers
      while IFS= read -r line; do
        local func_name=$(echo "$line" | sed -E 's/^[[:space:]]*function[[:space:]]+([A-Za-z0-9_]+).*/\1/')
        local func_sid=$(sanitize "func_${current_contract}_${func_name}")

        # Check which modifiers are applied
        while IFS= read -r mod; do
          [ -z "$mod" ] && continue
          if echo "$line" | grep -q "\b${mod}\b"; then
            emit "  $(sanitize "mod_${mod}") --> ${func_sid}[\"${func_name}()\"]:::func"
            has_content=true
          fi
        done <<< "$file_modifiers"

        # Check for onlyOwner, onlyRole, require(msg.sender)
        if echo "$line" | grep -q "onlyOwner"; then
          emit "  $(sanitize "role_Owner")[\"👤 Owner\"]:::role --> ${func_sid}[\"${func_name}()\"]:::func"
          has_content=true
        fi

      done < <(grep -E '^\s*function\s+[a-zA-Z].*\b(only|require)' "$file" 2>/dev/null | head -20 || true)

      # Also get external/public functions without modifiers (unrestricted)
      while IFS= read -r line; do
        local func_name=$(echo "$line" | sed -E 's/^[[:space:]]*function[[:space:]]+([A-Za-z0-9_]+).*/\1/')
        local has_modifier=false
        while IFS= read -r mod; do
          [ -z "$mod" ] && continue
          echo "$line" | grep -q "\b${mod}\b" && has_modifier=true
        done <<< "$file_modifiers"
        echo "$line" | grep -q "onlyOwner\|onlyRole\|only" && has_modifier=true

        if [ "$has_modifier" = false ]; then
          local func_sid=$(sanitize "func_${current_contract}_${func_name}")
          emit "  PublicAccess[\"🌐 Public\"] --> ${func_sid}[\"${func_name}()\"]:::func"
          has_content=true
        fi
      done < <(grep -E '^\s*function\s+[a-zA-Z].*(external|public)' "$file" 2>/dev/null | head -15 || true)

    done

  else
    # Rust/Anchor: #[access_control] and account constraints
    for file in "${FILES[@]}"; do
      while IFS= read -r line; do
        local constraint=$(echo "$line" | grep -oE 'has_one|constraint|signer|seeds' || true)
        local func_name=$(echo "$line" | sed -E 's/.*fn[[:space:]]+([a-z_][a-z0-9_]*).*/\1/' || true)
        if [ -n "$constraint" ]; then
          emit "  $(sanitize "check_${constraint}")[\"🔒 ${constraint}\"]:::modifier --> $(sanitize "fn_${func_name}")[\"${func_name}()\"]:::func"
          has_content=true
        fi
      done < <(grep -B2 -E '^\s*(pub\s+)?fn\s+' "$file" 2>/dev/null | grep -E 'has_one|constraint|signer|seeds|fn\s+' || true)
    done
  fi

  if [ "$has_content" = false ]; then
    emit "  NoAC[\"No access control patterns detected\"]"
  fi

  emit '```'
  emit ""
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 5: EXTERNAL DEPENDENCY GRAPH
# ════════════════════════════════════════════════════════════════

generate_dependency_diagram() {
  emit "## 5. External Dependency Graph"
  emit ""
  emit "Shows imported libraries, interfaces, and external contract dependencies."
  emit ""
  emit '```mermaid'
  emit "graph LR"
  emit "  classDef internal fill:#4a90d9,stroke:#2c5f8a,color:#fff"
  emit "  classDef openzeppelin fill:#7dc97d,stroke:#4a8a4a,color:#fff"
  emit "  classDef external fill:#d9a74a,stroke:#8a6a2c,color:#fff"
  emit "  classDef solmate fill:#9b7dd9,stroke:#5f4a8a,color:#fff"
  emit ""

  local has_edges=false
  local IMPORT_EDGES_SEEN=""

  if [ "$LANG_MODE" = "solidity" ]; then
    for file in "${FILES[@]}"; do
      local current_contract=$(grep -oE '(contract|abstract contract|library|interface)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
      [ -z "$current_contract" ] && continue

      while IFS= read -r import_line; do
        local import_path=$(echo "$import_line" | grep -oE '"[^"]*"' | tr -d '"')
        [ -z "$import_path" ] && continue

        local dep_name=""
        local dep_class="external"

        if echo "$import_path" | grep -qi "openzeppelin"; then
          dep_name=$(echo "$import_path" | grep -oE '[A-Z][A-Za-z0-9]+\.sol' | sed 's/\.sol//' || echo "OpenZeppelin")
          dep_class="openzeppelin"
        elif echo "$import_path" | grep -qi "solmate"; then
          dep_name=$(echo "$import_path" | grep -oE '[A-Z][A-Za-z0-9]+\.sol' | sed 's/\.sol//' || echo "Solmate")
          dep_class="solmate"
        elif echo "$import_path" | grep -qE '^\.\./|^\./'; then
          dep_name=$(echo "$import_path" | grep -oE '[A-Za-z0-9_]+\.sol' | sed 's/\.sol//')
          dep_class="internal"
        else
          dep_name=$(echo "$import_path" | grep -oE '[A-Za-z0-9_]+\.sol' | sed 's/\.sol//' || echo "$import_path")
        fi

        [ -z "$dep_name" ] && continue

        local edge_key="${current_contract}->${dep_name}"
        if ! echo "$IMPORT_EDGES_SEEN" | grep -qF "|${edge_key}|"; then
          IMPORT_EDGES_SEEN="${IMPORT_EDGES_SEEN}|${edge_key}|"
          emit "  $(sanitize "$current_contract")[\"${current_contract}\"]:::internal -->|imports| $(sanitize "dep_${dep_name}")[\"${dep_name}\"]:::${dep_class}"
          has_edges=true
        fi

      done < <(grep -E '^\s*import\s+' "$file" 2>/dev/null || true)
    done

  else
    # Rust: use/extern crate statements
    for file in "${FILES[@]}"; do
      local current_mod=$(basename "$file" .rs)

      while IFS= read -r use_line; do
        local dep=$(echo "$use_line" | sed -E 's/^[[:space:]]*(pub[[:space:]]+)?use[[:space:]]+([a-z_][a-z0-9_]*)::.*/\2/')
        [ -z "$dep" ] && continue
        [ "$dep" = "$use_line" ] && continue
        [ "$dep" = "std" ] || [ "$dep" = "core" ] || [ "$dep" = "alloc" ] && continue

        local dep_class="external"
        [ "$dep" = "anchor_lang" ] || [ "$dep" = "anchor_spl" ] && dep_class="openzeppelin"
        [ "$dep" = "solana_program" ] && dep_class="solmate"

        local edge_key="${current_mod}->${dep}"
        if ! echo "$IMPORT_EDGES_SEEN" | grep -qF "|${edge_key}|"; then
          IMPORT_EDGES_SEEN="${IMPORT_EDGES_SEEN}|${edge_key}|"
          emit "  $(sanitize "$current_mod") -->|uses| $(sanitize "dep_${dep}")[\"${dep}\"]:::${dep_class}"
          has_edges=true
        fi
      done < <(grep -E '^\s*(pub\s+)?use\s+[a-z]' "$file" 2>/dev/null | head -20 || true)
    done
  fi

  if [ "$has_edges" = false ]; then
    emit "  NoDeps[\"No external dependencies detected\"]"
  fi

  emit '```'
  emit ""
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 6: FUNCTION FLOW (ENTRY → INTERNAL → EXTERNAL)
# ════════════════════════════════════════════════════════════════

generate_function_flow() {
  emit "## 6. Function Flow Diagram"
  emit ""
  emit "Entry points (external/public) and their internal call chains."
  emit ""

  if [ "$LANG_MODE" = "solidity" ]; then
    for file in "${FILES[@]}"; do
      local current_contract=$(grep -oE '(contract|abstract contract)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
      [ -z "$current_contract" ] && continue

      # Collect external/public functions
      local ext_funcs=()
      while IFS= read -r line; do
        local fname=$(echo "$line" | sed -E 's/^[[:space:]]*function[[:space:]]+([A-Za-z0-9_]+).*/\1/')
        ext_funcs+=("$fname")
      done < <(grep -E '^\s*function\s+[a-zA-Z].*(external|public)' "$file" 2>/dev/null || true)

      [ ${#ext_funcs[@]} -eq 0 ] && continue

      # Collect internal/private functions
      local int_funcs=()
      while IFS= read -r line; do
        local fname=$(echo "$line" | sed -E 's/^[[:space:]]*function[[:space:]]+([A-Za-z0-9_]+).*/\1/')
        int_funcs+=("$fname")
      done < <(grep -E '^\s*function\s+_[a-zA-Z].*(internal|private)' "$file" 2>/dev/null || true)

      emit "### ${current_contract}"
      emit ""
      emit '```mermaid'
      emit "graph LR"
      emit "  classDef entry fill:#4a90d9,stroke:#2c5f8a,color:#fff"
      emit "  classDef internal fill:#d9a74a,stroke:#8a6a2c,color:#fff"
      emit "  classDef external_call fill:#d94a4a,stroke:#8a2c2c,color:#fff"
      emit ""

      # Add entry point nodes
      for func in "${ext_funcs[@]}"; do
        emit "  $(sanitize "${current_contract}_${func}")[\"🔵 ${func}()\"]:::entry"
      done

      # Check which internal functions are called by which external ones
      # This is approximate — looks for function name references in the file
      for ext_func in "${ext_funcs[@]}"; do
        # Get the function body (approximate: from function declaration to next function)
        for int_func in ${int_funcs[@]+"${int_funcs[@]}"}; do
          # Check if internal function is referenced in the external function's area
          local call_found=$(grep -A50 "function ${ext_func}" "$file" 2>/dev/null | grep -c "\b${int_func}\b" || echo "0")
          if [ "$call_found" -gt 0 ]; then
            emit "  $(sanitize "${current_contract}_${ext_func}") --> $(sanitize "${current_contract}_${int_func}")[\"🟡 ${int_func}()\"]:::internal"
          fi
        done

        # Check for external contract calls from this function
        local ext_calls=$(grep -A30 "function ${ext_func}" "$file" 2>/dev/null | grep -oE '[A-Z][A-Za-z0-9_]+\([^)]*\)\.[a-zA-Z]+' | sed 's/(.*//' | sort -u | head -5 || true)
        while IFS= read -r ext_call; do
          [ -z "$ext_call" ] && continue
          emit "  $(sanitize "${current_contract}_${ext_func}") --> $(sanitize "ext_${ext_call}")[\"🔴 ${ext_call}\"]:::external_call"
        done <<< "$ext_calls"
      done

      emit '```'
      emit ""
    done

  else
    # Rust/Anchor: instruction handlers
    for file in "${FILES[@]}"; do
      local current_mod=$(grep -oE '(pub\s+)?mod\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
      [ -z "$current_mod" ] && continue

      local pub_fns=()
      while IFS= read -r line; do
        local fname=$(echo "$line" | sed -E 's/^[[:space:]]*(pub[[:space:]]+)?fn[[:space:]]+([a-z_][a-z0-9_]*).*/\2/')
        pub_fns+=("$fname")
      done < <(grep -E '^\s*pub\s+fn\s+' "$file" 2>/dev/null | head -20 || true)

      [ ${#pub_fns[@]} -eq 0 ] && continue

      emit "### ${current_mod}"
      emit ""
      emit '```mermaid'
      emit "graph LR"
      emit "  classDef entry fill:#4a90d9,stroke:#2c5f8a,color:#fff"
      emit ""

      for func in "${pub_fns[@]}"; do
        emit "  $(sanitize "${current_mod}_${func}")[\"🔵 ${func}()\"]:::entry"
      done

      emit '```'
      emit ""
    done
  fi
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 7: COMPLEXITY HEATMAP (Summary Table)
# ════════════════════════════════════════════════════════════════

generate_complexity_summary() {
  emit "## 7. Complexity Heatmap"
  emit ""
  emit "Per-file metrics for quick complexity assessment."
  emit ""
  emit "| File | nSLOC | Functions | State Vars | External Calls | Modifiers | Complexity |"
  emit "|------|-------|-----------|------------|----------------|-----------|------------|"

  for file in "${FILES[@]}"; do
    local rel_path="${file#$TARGET/}"
    local contract_name=$(grep -oE '(contract|abstract contract|library|struct|mod)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
    [ -z "$contract_name" ] && contract_name=$(basename "$file" | sed 's/\.[^.]*$//')

    # Count nSLOC (simplified)
    local nsloc=$(perl -0777 -pe 's{/\*.*?\*/}{}gs' "$file" 2>/dev/null | sed -E '/^[[:space:]]*$/d; /^[[:space:]]*\/\//d; /^[[:space:]]*[{}][[:space:]]*$/d; /^[[:space:]]*(pragma|import|use |mod )/d' | wc -l | tr -d '[:space:]' || echo "0")

    local func_count=0
    local state_count=0
    local ext_calls=0
    local mod_count=0

    if [ "$LANG_MODE" = "solidity" ]; then
      func_count=$(grep -cE '^\s*function\s+' "$file" 2>/dev/null || echo "0")
      state_count=$(grep -cE '^\s+(mapping|uint|int|address|bool|bytes|string)\b' "$file" 2>/dev/null || echo "0")
      ext_calls=$(grep -cE '\.[a-z]+\(' "$file" 2>/dev/null || echo "0")
      mod_count=$(grep -cE '^\s*modifier\s+' "$file" 2>/dev/null || echo "0")
    else
      func_count=$(grep -cE '^\s*(pub\s+)?fn\s+' "$file" 2>/dev/null || echo "0")
      state_count=$(grep -cE '^\s*(pub\s+)?[a-z_]+\s*:' "$file" 2>/dev/null || echo "0")
      ext_calls=$(grep -cE 'invoke|invoke_signed|CpiContext' "$file" 2>/dev/null || echo "0")
      mod_count=$(grep -cE '#\[(access_control|constraint|has_one)' "$file" 2>/dev/null || echo "0")
    fi

    # Calculate complexity tier
    local complexity="🟢 LOW"
    local score=$((nsloc + func_count * 5 + state_count * 3 + ext_calls * 10))
    if [ "$score" -gt 500 ]; then
      complexity="🔴 CRITICAL"
    elif [ "$score" -gt 300 ]; then
      complexity="🟠 HIGH"
    elif [ "$score" -gt 100 ]; then
      complexity="🟡 MEDIUM"
    fi

    emit "| \`${rel_path}\` | ${nsloc} | ${func_count} | ${state_count} | ${ext_calls} | ${mod_count} | ${complexity} |"
  done

  emit ""
}

# ════════════════════════════════════════════════════════════════
# DIAGRAM 8: VALUE FLOW (ETH/TOKEN MOVEMENT)
# ════════════════════════════════════════════════════════════════

generate_value_flow() {
  emit "## 8. Value Flow Diagram"
  emit ""
  emit "Tracks ETH/token movement paths through the protocol."
  emit ""
  emit '```mermaid'
  emit "graph TD"
  emit "  classDef deposit fill:#4a90d9,stroke:#2c5f8a,color:#fff"
  emit "  classDef withdraw fill:#d94a4a,stroke:#8a2c2c,color:#fff"
  emit "  classDef transfer fill:#d9a74a,stroke:#8a6a2c,color:#fff"
  emit "  classDef mint fill:#7dc97d,stroke:#4a8a4a,color:#fff"
  emit ""

  local has_flow=false

  if [ "$LANG_MODE" = "solidity" ]; then
    for file in "${FILES[@]}"; do
      local current_contract=$(grep -oE '(contract|abstract contract)\s+[A-Za-z0-9_]+' "$file" 2>/dev/null | head -1 | awk '{print $NF}' || true)
      [ -z "$current_contract" ] && continue
      local csid=$(sanitize "$current_contract")

      # Detect deposit patterns (payable functions, safeTransferFrom into contract)
      local deposits=$(grep -nE 'function.*(deposit|stake|supply|addLiquidity).*payable|safeTransferFrom.*msg\.sender.*address\(this\)' "$file" 2>/dev/null | head -5 || true)
      if [ -n "$deposits" ]; then
        emit "  User_Deposit[\"💰 User Deposit\"]:::deposit --> ${csid}[\"${current_contract}\"]"
        has_flow=true
      fi

      # Detect withdraw patterns
      local withdrawals=$(grep -nE 'function.*(withdraw|unstake|redeem|removeLiquidity)|\.transfer\(|\.call\{value:' "$file" 2>/dev/null | head -5 || true)
      if [ -n "$withdrawals" ]; then
        emit "  ${csid}[\"${current_contract}\"] --> User_Withdraw[\"💸 User Withdraw\"]:::withdraw"
        has_flow=true
      fi

      # Detect internal transfers
      local transfers=$(grep -nE 'safeTransfer\(|\.transfer\(|transferFrom\(' "$file" 2>/dev/null | head -5 || true)
      if [ -n "$transfers" ]; then
        emit "  ${csid} -->|transfer| Token_Movement[\"🔄 Token Transfer\"]:::transfer"
        has_flow=true
      fi

      # Detect minting
      local mints=$(grep -nE '_mint\(|mint\(' "$file" 2>/dev/null | head -3 || true)
      if [ -n "$mints" ]; then
        emit "  ${csid} -->|mint| Mint_Event[\"🪙 Mint\"]:::mint"
        has_flow=true
      fi

    done
  fi

  if [ "$has_flow" = false ]; then
    emit "  NoValueFlow[\"No value flow patterns detected\"]"
  fi

  emit '```'
  emit ""
}

# ════════════════════════════════════════════════════════════════
# MAIN: Generate report
# ════════════════════════════════════════════════════════════════

emit "# 🐝 Scoping Bee — Codebase Complexity Visualizer"
emit ""
emit "**Target:** \`$TARGET\`"
emit "**Language:** $LANG_MODE"
emit "**Files analyzed:** ${#FILES[@]}"
emit "**Generated:** $(date '+%Y-%m-%d %H:%M:%S')"
emit ""
emit "---"
emit ""

# Extract metadata first
if [ "$LANG_MODE" = "solidity" ]; then
  extract_solidity_metadata
else
  extract_rust_metadata
fi

# Generate requested diagrams
case "$DIAGRAM_MODE" in
  all)
    generate_inheritance_diagram
    generate_call_graph
    generate_state_diagram
    generate_access_control_diagram
    generate_dependency_diagram
    generate_function_flow
    generate_complexity_summary
    generate_value_flow
    ;;
  inheritance) generate_inheritance_diagram ;;
  calls) generate_call_graph ;;
  state) generate_state_diagram ;;
  access) generate_access_control_diagram ;;
  deps) generate_dependency_diagram ;;
  flow) generate_function_flow ;;
  *)
    echo "Unknown diagram mode: $DIAGRAM_MODE"
    echo "Options: all, inheritance, calls, state, access, deps, flow"
    exit 1
    ;;
esac

emit "---"
emit ""
emit "*Generated by Scoping Bee Codebase Visualizer*"
emit "*Render these diagrams in GitHub, VS Code (Mermaid plugin), or [mermaid.live](https://mermaid.live)*"

flush
