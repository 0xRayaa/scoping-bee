# 🐝 Scoping Bee

**AI-powered pre-audit scoping for smart contract security audits.**

Scoping Bee automates the most critical (and most tedious) phase of a security audit — the initial scoping. Point it at a codebase and get a structured scope report with architectural context, attack surface enumeration, complexity scoring, and time estimates.

Supports **Solidity** (Foundry/Hardhat) and **Solana/Anchor** (Rust) codebases.

---

## Features

### 📥 Multi-Source Input
Accepts audit targets from multiple sources — no manual setup needed:

```bash
# GitHub repo
bash scripts/source_fetcher.sh https://github.com/org/repo

# Verified contract on any block explorer
bash scripts/source_fetcher.sh https://bscscan.com/address/0x1234...

# Raw address + chain
bash scripts/source_fetcher.sh 0x1234...abcd --chain bsc

# ZIP file from client
bash scripts/source_fetcher.sh ./contracts.zip

# Local directory
bash scripts/source_fetcher.sh ./src
```

**Supported explorers:** Etherscan, BSCScan, Polygonscan, Arbiscan, Optimism, Fantom, Avalanche, Base (+ testnets)

### 🛡️ Pre-Audit Threat Intelligence Scan
Every scoping session starts with a mandatory 10-phase threat intelligence scan. Untrusted audit codebases can contain shell injection, network exfiltration, phishing kits, supply chain attacks, and obfuscated payloads targeting auditor machines.

```bash
bash scripts/threat_intel_scan.sh ./target-repo
```

**10-Phase Scan Coverage:**
1. **Code Behavior Analysis** — lifecycle scripts, network exfiltration, obfuscated payloads, binaries, eval/exec
2. **HTML Fingerprint Matching** — phishing forms, hidden iframes, external scripts, tracking pixels, meta redirects
3. **Banner & Favicon Analysis** — brand impersonation detection via asset names, HTML titles, manifests
4. **Client-Side JS Inspection** — wallet access, cookie/storage theft, clipboard hijacking, script injection, crypto mining
5. **Post-Signature Distributor Check** — unlimited approvals, permit abuse, multicall drain patterns
6. **Codebase Profile Analysis** — repo age, contributor count, commit history, development patterns
7. **Function Purpose Analysis** — selfdestruct, delegatecall, admin backdoors, dangerous Solana patterns
8. **Dependency Audit** — typosquatted packages, unrelated dependencies, git deps, lock file anomalies
9. **Reachability Analysis** — orphan files, suspicious public functions, fallback entry points
10. **OSS Feed & Vuln Check** — tx.origin auth, outdated compilers, known vulnerable dependencies, npm audit

**Verdict:** `CLEAN` → proceed | `WARNING` → review first | `BLOCKED` → do not run any build commands

### 🗺️ Codebase Complexity Visualizer
Generate Mermaid diagrams to visually map code complexity, contract relationships, and attack surfaces:

```bash
# Generate all diagrams to a markdown file
bash scripts/codebase_visualizer.sh ./src --output complexity_map.md

# Generate only inheritance diagram
bash scripts/codebase_visualizer.sh ./src --diagram inheritance

# Include test files
bash scripts/codebase_visualizer.sh ./src --include-tests --output full_map.md
```

**8 Diagram Types:**
1. **Inheritance Hierarchy** — contract `is` chains and trait implementations
2. **Inter-Contract Call Graph** — which contracts call which
3. **State Variable Map** — class diagram of state vars and functions per contract
4. **Access Control Flow** — roles, modifiers, and protected function mapping
5. **External Dependency Graph** — OpenZeppelin, Solmate, custom imports
6. **Function Flow** — entry points → internal calls → external calls
7. **Complexity Heatmap** — per-file metrics table (nSLOC, functions, state vars, ext calls)
8. **Value Flow** — ETH/token deposit, withdraw, transfer, and mint paths

Render output in GitHub, VS Code (Mermaid plugin), or [mermaid.live](https://mermaid.live).

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
    ├── source_fetcher.sh           # Multi-source input fetcher (GitHub/Explorer/ZIP)
    ├── threat_intel_scan.sh         # Pre-audit threat intelligence scanner
    ├── codebase_visualizer.sh       # Mermaid diagram generator for complexity
    └── sloc_counter.sh             # Dual-language nSLOC counter
```

## Scoping Workflow

The skill runs **7 phases** in order:

```
Source Acquisition            → Fetch from GitHub / Explorer / ZIP / Local
Phase 0: Threat Intel Scan    → CLEAN / WARNING / BLOCKED
Phase 1: Codebase Ingestion   → Contract inventory, nSLOC, dependencies
Phase 2: Architectural Context → Protocol type, value flow, trust boundaries
Phase 3: System Mapping        → Per-contract entry points, state, roles
Phase 4: Attack Surface Enum   → 24 EVM or 18 Solana checks
Phase 5: Complexity Scoring    → 5-metric weighted score per contract
Phase 6: Report Assembly       → Structured scope document
```

**Output:** A structured `<protocol>_scope_report.md` with:
- Executive summary
- Threat intelligence scan results
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
- 🟢 **LOW** (1.0–1.5) → Checklist review
- 🟡 **MEDIUM** (1.6–2.5) → Vector scan methodology
- 🟠 **HIGH** (2.6–3.5) → Deep interrogation methodology
- 🔴 **CRITICAL** (3.6–4.0) → Full methodology + invariant extraction + PoC

## Quick Start

### Standalone Scripts

```bash
# Fetch from GitHub
bash scripts/source_fetcher.sh https://github.com/org/repo

# Fetch verified contract from BSCScan
bash scripts/source_fetcher.sh https://bscscan.com/address/0x1234... --api-key YOUR_KEY

# Fetch by address + chain
bash scripts/source_fetcher.sh 0xAbCd...1234 --chain polygon

# Extract a ZIP
bash scripts/source_fetcher.sh ./client-contracts.zip --output ./audit-target

# Threat intel scan a repo before opening it
bash scripts/threat_intel_scan.sh /path/to/audit/repo

# Generate Mermaid complexity diagrams
bash scripts/codebase_visualizer.sh /path/to/src --output complexity_map.md

# Count nSLOC with effort estimate
bash scripts/sloc_counter.sh /path/to/src --pace 350

# Count Rust/Solana nSLOC
bash scripts/sloc_counter.sh /path/to/programs --lang rust --pace 300
```

### As an AI Skill

When integrated with an AI coding assistant, simply ask:
> "Scope the audit for https://github.com/org/repo"  
> "Scope this contract: 0x1234... on BSC"  
> "Scope the audit for ./src"

The skill auto-triggers on keywords: *scope*, *scoping*, *audit complexity*, *scope document*.

## License

MIT

---

*Built for auditors, by auditors. Stop wasting time on manual scoping.*
