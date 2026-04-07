# 🐝 Scoping Bee

**AI-powered pre-audit scoping for smart contract security audits.**

Scoping Bee automates the most critical (and most tedious) phase of a security audit — the initial scoping. Point it at a codebase and get a structured scope report with architectural context, attack surface enumeration, complexity scoring, and time estimates.

Supports **Solidity** (Foundry/Hardhat) and **Solana/Anchor** (Rust) codebases.

---

## Features

### 🛡️ Pre-Audit Malware Scan
Every scoping session starts with a mandatory malware scan. Untrusted audit codebases can contain shell injection, network exfiltration, and obfuscated payloads targeting auditor machines.

```bash
bash scripts/malware_scan.sh ./target-repo
```

**Checks for:**
- npm lifecycle scripts (`postinstall`, `preinstall`) that execute code
- Network calls (`curl`, `wget`, `fetch`) in scripts
- Base64-encoded payloads and suspicious binaries
- Symlinks pointing outside the repo
- Forge FFI (`vm.ffi()`) and `eval`/`exec` patterns
- Hidden files and keypair references

**Verdict:** `CLEAN` → proceed | `WARNING` → review first | `BLOCKED` → do not run any build commands

### 📊 Configurable Audit Pace
Effort estimation uses a configurable **lines-of-code per day** rate:

```bash
# Default: 350 nSLOC/day
bash scripts/sloc_counter.sh ./src

# High-complexity code: 300 nSLOC/day
bash scripts/sloc_counter.sh ./src --pace 300

# Simple patterns: 400 nSLOC/day
bash scripts/sloc_counter.sh ./src --pace 400
```

The pace is always displayed in the output so users can recalculate with their own rate.

### 🔍 Dual Language Support
Auto-detects Solidity or Rust/Anchor and applies the correct analysis:

| Feature | Solidity | Rust/Anchor |
|---------|----------|-------------|
| nSLOC counting | Strips pragma, imports, SPDX | Strips use, mod, attributes |
| Attack surfaces | 24 EVM-specific checks | 18 Solana-specific checks |
| System mapping | Functions, modifiers, events | Instructions, PDAs, CPIs |
| Framework detection | Foundry / Hardhat | Anchor / Native Solana |

### 🎯 42 Attack Surface Checks
Comprehensive checklists with trigger conditions for each surface:

**EVM (24):** Reentrancy, proxy patterns, authorization bypass, oracle manipulation, share inflation, flash loans, precision loss, MEV, signature replay, gas griefing, and more.

**Solana (18):** Missing signer, PDA seed confusion, CPI exploits, type cosplay, account closure bugs, reinitialization, remaining accounts, lamport manipulation, and more.

---

## Skill Structure

```
scoping-bee/
├── SKILL.md                    # Core AI skill instructions
├── README.md                   # This file
├── references/
│   ├── scope-report-template.md    # Output template for scope reports
│   ├── attack-surfaces.md          # 42 attack surface checklists (EVM + Solana)
│   └── complexity-rubric.md        # 5-metric scoring rubric + effort estimation
└── scripts/
    ├── malware_scan.sh             # Pre-audit malware scanner
    └── sloc_counter.sh             # Dual-language nSLOC counter
```

## Scoping Workflow

The skill runs **6 phases** in order:

```
Phase 0: Malware Scan        → CLEAN / WARNING / BLOCKED
Phase 1: Codebase Ingestion   → Contract inventory, nSLOC, dependencies
Phase 2: Architectural Context → Protocol type, value flow, trust boundaries
Phase 3: System Mapping        → Per-contract entry points, state, roles
Phase 4: Attack Surface Enum   → 24 EVM or 18 Solana checks
Phase 5: Complexity Scoring    → 5-metric weighted score per contract
Phase 6: Report Assembly       → Structured scope document
```

**Output:** A structured `<protocol>_scope_report.md` with:
- Executive summary
- Malware scan results
- Contract inventory with nSLOC
- Architectural context JSON
- Per-contract system maps
- Attack surface matrix
- Complexity scores and risk tiers
- Prioritized audit hitlist
- Recommended methodology per contract
- Effort estimation with configurable pace

## Complexity Scoring

Each contract is scored on 5 weighted metrics:

| Metric | Weight |
|--------|--------|
| nSLOC | 25% |
| External Integration Risk | 25% |
| State Coupling | 20% |
| Access Control Complexity | 15% |
| Upgradeability Risk | 15% |

**Risk Tiers:**
- 🟢 **LOW** (1.0–1.5) → Standard checklist review
- 🟡 **MEDIUM** (1.6–2.5) → Vector scan methodology
- 🟠 **HIGH** (2.6–3.5) → Deep interrogation methodology
- 🔴 **CRITICAL** (3.6–4.0) → Full methodology + invariant extraction + PoC

## Quick Start

### Standalone Scripts

```bash
# Malware scan a repo before opening it
bash scripts/malware_scan.sh /path/to/audit/repo

# Count nSLOC with effort estimate
bash scripts/sloc_counter.sh /path/to/src --pace 350

# Count Rust/Solana nSLOC
bash scripts/sloc_counter.sh /path/to/programs --lang rust --pace 300
```

### As an AI Skill

When integrated with an AI coding assistant, simply ask:
> "Scope the audit for ./src"

The skill auto-triggers on keywords: *scope*, *scoping*, *audit complexity*, *scope document*.

## License

MIT

---

*Built for auditors, by auditors. Stop wasting time on manual scoping.*
