# Scoping Bee

This is a smart contract security audit scoping tool. When the user provides a **GitHub URL**, **ZIP file**, or **contract address**, automatically run the full scoping pipeline.

## Quick Start

The user will give you one of these inputs:
- A GitHub link (e.g., `https://github.com/org/repo`)
- A ZIP file path (e.g., `./contracts.zip`)
- A block explorer URL (e.g., `https://etherscan.io/address/0x...`)
- A contract address with chain (e.g., `0x... --chain bsc`)
- A local directory path

**When any of these is provided, immediately run the full scoping pipeline without asking questions.**

## Pipeline (run in order)

### Step 1: Fetch Source
```bash
bash <project_root>/scripts/source_fetcher.sh <input> --output ./audit-target [OPTIONS]
```

### Step 2: Threat Intel Scan (MANDATORY)
```bash
bash <project_root>/scripts/threat_intel_scan.sh ./audit-target
```
- If HIGH findings → STOP and report to user
- If MEDIUM findings → WARN and ask to confirm
- If clean → continue

### Step 3: Count nSLOC
```bash
bash <project_root>/scripts/sloc_counter.sh ./audit-target [--lang solidity|rust]
```
Mock files are automatically excluded from the count.

### Step 4: Visualize Codebase
```bash
bash <project_root>/scripts/codebase_visualizer.sh ./audit-target
```

### Step 5: Full Analysis (Phases 1-6)
Follow the complete methodology in [SKILL.md](SKILL.md):
1. **Codebase Ingestion** — detect language, discover files, count nSLOC, detect deps
2. **Architectural Context** — protocol type, chain, token model, trust boundaries
3. **System Mapping** — per-contract entry points, state, roles, external calls
4. **Attack Surface Enumeration** — use [attack-surfaces.md](references/attack-surfaces.md)
5. **Complexity & Risk** — use [complexity-rubric.md](references/complexity-rubric.md)
6. **Scope Report** — output using [scope-report-template.md](references/scope-report-template.md)

### Step 6: Output Report
Save as `<protocol_name>_scope_report.md` in the current working directory.

## Key Rules

- `<project_root>` = the directory containing this CLAUDE.md file
- Default audit pace: **350 nSLOC/day** (user can override)
- Always exclude mock/test/script files from nSLOC calculation
- Always run threat intel scan before analysis
- Always state the audit pace used in the final report

## Setup for New Scoping Projects

To use this in any directory, copy or symlink the `.claude/` folder and point it to this repo:
```bash
# From your new scoping directory:
mkdir -p .claude
cat > CLAUDE.md << 'EOF'
# Scoping Project
Use the scoping-bee skill at /path/to/scoping-bee for all audit scoping tasks.
When given a GitHub URL, ZIP, or contract address, run the full scoping pipeline from SKILL.md.
EOF
```
