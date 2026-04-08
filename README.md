<div align="center">

# 🐝 Scoping Bee

**`━━━━⬡⬡⬡━━━━ AI-POWERED AUDIT SCOPING ━━━━⬡⬡⬡━━━━`**

*Point it at a codebase. Get a structured scope report.*

**Solidity** (Foundry/Hardhat) · **Solana/Anchor** (Rust)

</div>

---

<div align="center">

### ⬡ THE HIVE ⬡

</div>

Scoping Bee automates the most critical (and most tedious) phase of a security audit — the initial scoping. Give it a codebase and receive a bee-themed scope report with flow diagrams, complexity scoring, prioritized hitlists, and time estimates.

```
  ⬡─────────────────────────────────────────────────────────────⬡
  │                                                              │
  │  📥 Source Fetch  →  🛡️ Threat Scan  →  📊 Analysis  →  🐝 Report │
  │                                                              │
  ⬡─────────────────────────────────────────────────────────────⬡
```

---

<div align="center">

### ⬡ As an AI Skill ⬡

When integrated with an AI coding assistant, simply ask:

> "Scope the audit for https://github.com/org/repo" 
> "Scope this contract: 0x1234... on BSC" 
> "Scope the audit for ./src" 


### ⬡ FEATURES ⬡

</div>

## 📥 Multi-Source Input

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

---

## 🛡️ Pre-Audit Threat Intelligence Scan

Every scoping session starts with a mandatory **10-phase** hive security sweep. Untrusted audit codebases can contain shell injection, network exfiltration, phishing kits, supply chain attacks, and obfuscated payloads targeting auditor machines.

```bash
bash scripts/threat_intel_scan.sh ./target-repo
```

```
┌─────────────────────────────────────────────────────────┐
│  🐝 HIVE SECURITY SWEEP — 10 PHASES                     │
├─────────────────────────────────────────────────────────┤
│  ⬡ Phase 1   Code Behavior Analysis          (HIGH)    │
│  ⬡ Phase 2   HTML Fingerprint Matching        (MED-HI) │
│  ⬡ Phase 3   Banner & Favicon Analysis        (HIGH)   │
│  ⬡ Phase 4   Client-Side JS Inspection        (MED-HI) │
│  ⬡ Phase 5   Post-Signature Distributor Check  (HIGH)   │
│  ⬡ Phase 6   Codebase Profile Analysis        (MED)    │
│  ⬡ Phase 7   Function Purpose Analysis        (MED-HI) │
│  ⬡ Phase 8   Dependency Audit                 (HIGH)   │
│  ⬡ Phase 9   Reachability Analysis            (MED)    │
│  ⬡ Phase 10  OSS Feed & Vuln Check            (MED-HI) │
├─────────────────────────────────────────────────────────┤
│  Verdict: CLEAN ✅ / WARNING ⚠️ / BLOCKED 🛑            │
└─────────────────────────────────────────────────────────┘
```

---

## 🗺️ Codebase Complexity Visualizer

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

| # | Diagram | What it shows |
|--:|:--------|:-------------|
| 1 | Inheritance Hierarchy | Contract `is` chains and trait implementations |
| 2 | Inter-Contract Call Graph | Which contracts call which |
| 3 | State Variable Map | Class diagram of state vars and functions |
| 4 | Access Control Flow | Roles, modifiers, and protected functions |
| 5 | External Dependency Graph | OpenZeppelin, Solmate, custom imports |
| 6 | Function Flow | Entry points → internal → external calls |
| 7 | Complexity Heatmap | Per-file metrics table |
| 8 | Value Flow | Token deposit, withdraw, transfer paths |

---

## 📊 Configurable Audit Pace

Effort estimation uses a configurable **lines-of-code per day** rate:

```bash
# Default: 350 nSLOC/day
bash scripts/sloc_counter.sh ./src

# High-complexity code: 300 nSLOC/day
bash scripts/sloc_counter.sh ./src --pace 300

# Simple patterns: 400 nSLOC/day
bash scripts/sloc_counter.sh ./src --pace 400
```

---

## 🔍 Dual Language Support

Auto-detects Solidity or Rust/Anchor and applies the correct analysis:

| Feature | Solidity | Rust/Anchor |
|:--------|:---------|:------------|
| nSLOC counting | Strips pragma, imports, SPDX | Strips use, mod, attributes |
| Attack surfaces | 24 EVM-specific checks | 18 Solana-specific checks |
| System mapping | Functions, modifiers, events | Instructions, PDAs, CPIs |
| Framework detection | Foundry / Hardhat | Anchor / Native Solana |

---

## 🎯 42 Attack Surface Checks

| EVM (24) | Solana (18) |
|:---------|:------------|
| Reentrancy, proxy patterns, auth bypass | Missing signer, PDA seed confusion |
| Oracle manipulation, share inflation | CPI exploits, type cosplay |
| Flash loans, precision loss, MEV | Account closure, reinitialization |
| Signature replay, gas griefing | Remaining accounts, lamport manipulation |

---

<div align="center">

### ⬡ HIVE STRUCTURE ⬡

</div>

```
  scoping-bee/
  ├── 📋 CLAUDE.md                          # Pipeline instructions
  ├── 📖 SKILL.md                           # Core methodology
  ├── 📄 README.md                          # This file
  │
  ├── 🍯 references/
  │   ├── scope-report-template.md          # Bee-themed output template
  │   ├── attack-surfaces.md                # 42 attack surface checklists
  │   └── complexity-rubric.md              # 5-metric scoring rubric
  │
  └── 🔧 scripts/
      ├── source_fetcher.sh                 # Multi-source input fetcher
      ├── threat_intel_scan.sh              # 10-phase threat scanner
      ├── codebase_visualizer.sh            # Mermaid diagram generator
      └── sloc_counter.sh                   # Dual-language nSLOC counter
```

---

<div align="center">

### ⬡ SCOPING WORKFLOW ⬡

</div>

```
  ⬡─────────────────────────────────────────────────────────────⬡
  │                                                              │
  │  1. 📥 Source Acquisition                                   │
  │         │   GitHub / Explorer / ZIP / Local                  │
  │         │                                                    │
  │  2. 🛡️ Threat Intel Scan (MANDATORY)                       │
  │         │   CLEAN → proceed / BLOCKED → stop                 │
  │         │                                                    │
  │  3. 🔍 Codebase Ingestion                                  │
  │         │   Contract inventory, nSLOC, dependencies          │
  │         │                                                    │
  │  4. 🔀 Flow Diagram & Dependencies                         │
  │         │   Value flow, cross-contract calls, trust map      │
  │         │                                                    │
  │  5. 🔬 Complexity & Risk Scoring                            │
  │         │   5-metric weighted score per contract              │
  │         │                                                    │
  │  6. 🐝 Report Assembly                                     │
  │         │   Bee-themed scope document                        │
  │                                                              │
  ⬡─────────────────────────────────────────────────────────────⬡
```

**Output:** A structured `<protocol>_scope_report.md` with:

| Section | Content |
|:--------|:--------|
| 🛡️ Threat Scan | Hive security sweep results |
| 📋 Executive Summary | Protocol at a glance |
| ⏱️ Estimated Effort | Days breakdown with complexity multipliers |
| 📦 Contract Inventory | The Honeycomb — contracts with bee roles |
| 🔀 Flow Diagram | The Waggle Dance — value flow + dependencies |
| 🔬 Complexity Scores | Per-contract weighted scoring |
| 🎯 Audit Hitlist | Sting Zone / Watch Zone / Low Pollen |
| 🛠️ Methodology | Recommended approach per contract |
| ❓ Open Questions | Items for protocol team |

---

<div align="center">

### ⬡ COMPLEXITY SCORING ⬡

</div>

Each contract is scored on 5 weighted metrics:

| Metric | Weight |
|:-------|-------:|
| nSLOC | 25% |
| External Integration Risk | 25% |
| State Coupling | 20% |
| Access Control Complexity | 15% |
| Upgradeability Risk | 15% |

**Risk Tiers:**

```
  🟢 LOW      (1.0–1.5)  →  Checklist review         — Low Pollen
  🟡 MEDIUM   (1.6–2.5)  →  Vector scan               — Watch Zone
  🟠 HIGH     (2.6–3.5)  →  Deep interrogation         — Sting Zone
  🔴 CRITICAL (3.6–4.0)  →  Full methodology + PoC     — Critical Sting Zone
```

---

<div align="center">

### ⬡ QUICK START ⬡

</div>

### 🔧 Standalone Scripts

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
---

## License

MIT

---

<div align="center">

```
  ⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡
  🐝  Built for auditors, by auditors.                     🍯
      Stop wasting time on manual scoping.
  ⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡
```

</div>
