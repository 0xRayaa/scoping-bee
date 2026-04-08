---
name: scoping-bee
description: >-
  Perform structured pre-audit scoping for smart contract security audits
  (Solidity and Solana/Anchor). Analyzes a codebase to produce flow diagrams,
  complexity scoring, prioritized hitlists, and a bee-themed scope report with
  configurable auditor pace. Includes pre-scoping threat intelligence scan.
  Use when starting a new audit, scoping a contract, evaluating audit complexity,
  or preparing a scope document for a security engagement.
---

# 🐝 Scoping Bee

**`━━━━⬡⬡⬡━━━━ SKILL METHODOLOGY ━━━━⬡⬡⬡━━━━`**

Systematic pre-audit scoping for smart contract security engagements.
Supports **Solidity** (Foundry/Hardhat) and **Solana/Anchor** (Rust) codebases.

Produces a bee-themed scope report with configurable effort estimation that
feeds directly into deep audit methodologies (vector scanning,
threat interrogation, invariant extraction).

---

<div align="center">

### ⬡ CONFIGURATION ⬡

</div>

## Auditor Pace (Lines of Code per Day)

The default audit pace is **350 nSLOC/day**. Adjust this based on:
- Auditor experience level
- Code complexity (drop to ~300 for high-complexity code)
- Familiarity with the protocol pattern

When the user specifies a custom pace, use their value throughout.
If unspecified, use 350.

```
AUDIT_PACE=350  # nSLOC per day (default)
```

**Examples:**
- "Scope this at 300 lines/day" → `AUDIT_PACE=300`
- "Use my normal pace" → `AUDIT_PACE=350` (default)
- "I can do 400/day for simple ERC20s" → `AUDIT_PACE=400`

When presenting the final effort estimate, always state the pace used so
the user can re-calculate if they adjust later.

---

<div align="center">

### ⬡ INVOCATION ⬡

</div>

## Invocation

When the user provides a **GitHub URL**, **ZIP file**, **contract address**, **explorer URL**,
or **local directory path**, immediately start the scoping pipeline — no questions asked.

### Auto-Trigger Inputs

Any of these inputs should trigger the full pipeline automatically:
- `https://github.com/org/repo` — GitHub URL
- `./contracts.zip` — ZIP archive
- `https://etherscan.io/address/0x...` — Block explorer URL
- `0x1234...abcd --chain bsc` — Raw contract address
- `./src` or `./contracts` — Local directory

### Pipeline Steps

1. **Fetch source** — run `source_fetcher.sh` to normalize input into `./audit-target`
2. **Threat scan** — run `threat_intel_scan.sh` on the fetched source (MANDATORY)
3. **Proceed if clean** — run Phases 1–6 on the normalized source
4. **Output report** — save as `<protocol_name>_scope_report.md` using the template
   in [scope-report-template.md](references/scope-report-template.md)

### Decision Logic After Threat Scan

```
If HIGH severity findings → STOP. Report findings. Ask user to review.
If MEDIUM severity findings → WARN. Show findings. Ask user to confirm proceed.
If only LOW/NONE → Proceed automatically to Phase 1.
```

---

<div align="center">

### ⬡ SOURCE ACQUISITION ⬡

</div>

## Source Acquisition

The skill accepts **4 input types**, auto-detected:

| Input | Example | What Happens |
|-------|---------|-------------|
| **GitHub URL** | `https://github.com/org/repo` | Shallow clone (`--depth 1`) |
| **Explorer URL** | `https://bscscan.com/address/0x1234...` | Fetch verified source via API |
| **Contract address** | `0x1234...abcd` (+ `--chain bsc`) | Fetch verified source via API |
| **ZIP file** | `./contracts.zip` | Extract and flatten |
| **Local directory** | `./src` | Use as-is |

### Source Fetcher Script

```bash
bash <skill_dir>/scripts/source_fetcher.sh <input> [OPTIONS]
```

**Options:**
- `--output <dir>` — Output directory (default: `./audit-target`)
- `--chain <chain>` — Chain for address input (eth, bsc, polygon, arbitrum, etc.)
- `--api-key <key>` — Block explorer API key (or set `EXPLORER_API_KEY` env var)
- `--branch <branch>` — Git branch to clone (default: main)

### Supported Block Explorers

| Chain | Explorer | API |
|-------|----------|-----|
| Ethereum | etherscan.io | ✅ |
| Goerli | goerli.etherscan.io | ✅ |
| Sepolia | sepolia.etherscan.io | ✅ |
| BSC | bscscan.com | ✅ |
| BSC Testnet | testnet.bscscan.com | ✅ |
| Polygon | polygonscan.com | ✅ |
| Arbitrum | arbiscan.io | ✅ |
| Optimism | optimistic.etherscan.io | ✅ |
| Fantom | ftmscan.com | ✅ |
| Avalanche | snowtrace.io | ✅ |
| Base | basescan.org | ✅ |

### Decision Logic

```
If input is a GitHub URL      → clone repo → proceed to Phase 0
If input is an explorer URL   → extract address + chain from URL → fetch via API → proceed
If input is a raw 0x address  → require --chain flag → fetch via API → proceed
If input is a .zip file       → extract → flatten single root dir → proceed
If input is a local directory → use directly → proceed
```

**For block explorer inputs:**
- The script writes a `.explorer_metadata.json` with contract name, compiler
  version, optimization settings, and proxy status
- ABI is saved alongside source files
- If the contract is a **proxy**, the script warns — you should also fetch the
  implementation contract

---

<div align="center">

### ⬡ PHASE 0 — THREAT SCAN ⬡

</div>

## Phase 0: Threat Intelligence Scan ⚠️ MANDATORY

**Run this BEFORE any other analysis.** Untrusted audit codebases can contain
malware, phishing kits, supply chain attacks, and backdoors targeting auditor machines.

```bash
bash <skill_dir>/scripts/threat_intel_scan.sh <project_root>
```

The scan performs **10 phases** of deep threat analysis:

### Phase 1: Code Behavior Analysis (HIGH)
- **Auto-exec lifecycle scripts**: npm `postinstall`/`preinstall` hooks
- **Network exfiltration**: `curl`, `wget`, `fetch`, `sendBeacon`, outbound HTTP
- **Obfuscated payloads**: Base64 strings, hex-encoded shellcode
- **Suspicious binaries**: Compiled executables, `.so`/`.dylib`/`.bin` files
- **External symlinks**: Links pointing outside the repo
- **Dynamic code execution**: `eval`, `exec`, `spawn`, `child_process`, `Function()`
- **Forge FFI**: `vm.ffi()` calls in Solidity

### Phase 2: HTML Fingerprint Matching (MEDIUM–HIGH)
- Phishing form patterns (credential harvesting templates)
- Hidden iframes (clickjacking / drive-by downloads)
- External script injection from unverified domains
- Tracking pixels / data beacons
- Meta refresh auto-redirects
- Heavy HTML entity / Unicode escape obfuscation

### Phase 3: Banner & Favicon Analysis (HIGH)
- Asset names matching known crypto brands (MetaMask, Phantom, Uniswap, etc.)
- HTML titles impersonating DeFi protocols
- Manifest.json brand impersonation

### Phase 4: Client-Side JS Inspection (MEDIUM–HIGH)
- Wallet API access / private key material handling
- Cookie, localStorage, sessionStorage theft patterns
- Clipboard hijacking (address swap attacks)
- Dynamic script injection into DOM
- WebSocket C2 communication channels
- JS obfuscation (packed code, hex encoding, `atob`/`fromCharCode`)
- Keyboard event listeners (keylogging)
- Cryptocurrency mining patterns

### Phase 5: Post-Signature Distributor Check (HIGH)
- Unlimited token approval patterns (MaxUint256 approve)
- Post-signature callback execution chains
- EIP-712 / Permit gasless approval abuse
- Multicall + transfer batch drain patterns

### Phase 6: Codebase Profile Analysis (MEDIUM)
- Repository age (new repos = higher risk)
- Contributor count and commit history depth
- History rewriting (force push, rebase, amend patterns)
- Code dump detection (minimal commits, not organic development)

### Phase 7: Function Purpose Analysis (MEDIUM–HIGH)
- `selfdestruct` / `suicide` in Solidity contracts
- Arbitrary `delegatecall` patterns
- Admin backdoor functions (ownership transfer, admin change)
- Rust/Anchor: unchecked accounts, CPI invocations

### Phase 8: Dependency Audit (HIGH)
- Known malicious / typosquatted npm packages (curated blocklist)
- Unrelated packages for smart contract repos (puppeteer, nodemailer, etc.)
- Git-based dependencies (bypass npm registry)
- Lock file resolution from suspicious URLs (pastebin, gist, etc.)
- Custom/private registry references
- Dependency bloat assessment

### Phase 9: Reachability Analysis (MEDIUM)
- Orphan files not imported anywhere (hidden payload indicators)
- Suspicious externally-callable function names (drain, sweep, execute)
- Fallback/receive with logic (reentrancy entry surfaces)

### Phase 10: OSS Feed & Vulnerability Check (MEDIUM–HIGH)
- `tx.origin` authentication (phishable)
- Unchecked call return values
- Outdated Solidity versions with known compiler bugs
- Floating pragmas
- Outdated OpenZeppelin / solc versions
- npm audit integration (critical/high vulns)

### Decision Logic

```
If HIGH severity findings → STOP. Report findings. Ask user to review.
If MEDIUM severity findings → WARN. Show findings. Ask user to confirm proceed.
If only LOW/NONE → Proceed automatically to Phase 1.
```

**Always show the threat intelligence scan summary** in the scope report regardless of
findings, so the user knows it was checked.

**Do NOT include false positive counts** in the threat scan results. Only show
the category checks and their pass/fail status. Mentioning false positive numbers
can cause unnecessary concern.

---

<div align="center">

### ⬡ PHASE 1 — CODEBASE INGESTION ⬡

</div>

## Phase 1: Codebase Ingestion

### 1.1 Detect Language & Framework

| Indicator | Language | Framework |
|-----------|----------|-----------|
| `.sol` files + `foundry.toml` | Solidity | Foundry |
| `.sol` files + `hardhat.config.*` | Solidity | Hardhat |
| `.rs` files + `Anchor.toml` | Rust | Anchor (Solana) |
| `.rs` files + `Cargo.toml` (no Anchor) | Rust | Native Solana |

### 1.2 Discover In-Scope Files

**Solidity:**
```bash
find <src_dir> -name "*.sol" \
  ! -path "*/test/*" ! -path "*/tests/*" \
  ! -path "*/mock/*" ! -path "*/mocks/*" \
  ! -path "*/script/*" ! -path "*/scripts/*" \
  ! -path "*/node_modules/*" ! -path "*/lib/*" \
  ! -name "Mock*" ! -name "mock*" \
  ! -name "*Mock.sol" ! -name "*mock.sol" | sort
```

**Rust/Anchor:**
```bash
find <programs_dir> -name "*.rs" \
  ! -path "*/tests/*" ! -path "*/test/*" \
  ! -path "*/target/*" ! -name "mod.rs" \
  ! -path "*/mock/*" ! -path "*/mocks/*" \
  ! -name "mock_*" ! -name "*_mock.rs" | sort
```

Classify each file as:
- **Core**: Business logic (state changes, value flows)
- **Interface**: Trait definitions, abstract contracts
- **Library**: Stateless helpers
- **Dependency**: Third-party code (OZ, Solmate, anchor-spl)

### 1.3 Count nSLOC

```bash
bash <skill_dir>/scripts/sloc_counter.sh <file_or_directory> [--lang solidity|rust]
```

### 1.4 Detect Dependencies

Parse `foundry.toml`/`Cargo.toml`/`package.json` for external deps with versions.

---

<div align="center">

### ⬡ PHASE 2 — FLOW DIAGRAM ⬡

</div>

## Phase 2: Flow Diagram & Dependencies

Produce a **Mermaid flow diagram** showing:
- How value enters, flows through, and exits the protocol
- Cross-contract/program call relationships and data flow
- Trust assumptions between components

For Solana/Anchor programs, also capture in the diagram:
- **PDA derivation** flows
- **CPI targets** (cross-program invocations)
- **Signer authority** model

Include a **Trust Assumptions** table mapping: From → To → Assumption → Risk if Broken.

**Do NOT output raw JSON for architectural context.** Use the flow diagram to
communicate architecture visually.

**Do NOT include a separate System Maps section** with per-contract JSON.
The contract inventory table and flow diagram provide sufficient structural detail.

---

<div align="center">

### ⬡ PHASE 3 — COMPLEXITY SCORING ⬡

</div>

## Phase 3: Complexity & Risk Estimation

**Note:** The Attack Surface Matrix is NOT included in the report. Attack surface
analysis is performed internally to inform complexity scoring and the prioritized
audit hitlist, but the full matrix is omitted from the scope report.

---

Score each contract/program using the rubric in
[complexity-rubric.md](references/complexity-rubric.md).

### Effort Calculation

```
audit_days = total_nSLOC / AUDIT_PACE
```

Where `AUDIT_PACE` defaults to 350 nSLOC/day unless the user specifies otherwise.

**Always include in the report:**
```
Audit pace used: [N] nSLOC/day
Total nSLOC: [M]
Estimated days: [M/N] = [X] days
```

Apply complexity multipliers from the rubric for per-contract breakdowns.

**Estimated Effort must appear near the top of the report** (right after Executive Summary),
not at the bottom. This is the most actionable information for the client.

---

<div align="center">

### ⬡ PHASE 4 — REPORT ASSEMBLY ⬡

</div>

## Phase 4: Scope Report Assembly

Use the template at [scope-report-template.md](references/scope-report-template.md).

Output as: `<protocol_name>_scope_report.md`

### Report Section Order

The scope report uses **honeycomb-numbered sections** (`⬡ HIVE SECTION N ⬡`):

1. 🛡️ Threat Intelligence Scan — ASCII box with per-check status
2. 📋 Executive Summary — ASCII box with key metrics
3. ⏱️ **Estimated Effort** — ASCII box + detailed table (positioned high for visibility)
4. 📦 Contract Inventory — "The Honeycomb" with bee role assignments
5. 🔀 Flow Diagram — "The Waggle Dance" with amber-themed Mermaid
6. 🔬 Complexity & Risk Scores — with ASCII scoring rationale
7. 🎯 Prioritized Audit Hitlist — split by P0/P1/P2 ("Sting Zone" / "Watch Zone" / "Low Pollen")
8. 🛠️ Recommended Methodology — with hexagonal audit flow
9. ❓ Open Questions — numbered table format
10. 📎 Appendix: Files Out of Scope

### 🐝 Bee Theme Guidelines

The report uses a consistent bee/hive visual language:

**Section dividers**: Each section is preceded by `⬡ HIVE SECTION N ⬡` centered.

**Contract roles** (assign based on responsibility):
- 👑 **Queen** — main orchestrator / entry point
- 🏗️ **Builder** — state management / core logic
- 🔧 **Worker** — utility / encoding / helpers
- 🐝 **Guard** — access control / authorization
- 🍯 **Honeypot** — value storage / treasury

**Visual elements**:
- ASCII boxes (`┌─┐ │ │ └─┘`) for key summaries (threat scan, executive summary, effort)
- Honeycomb separators (`⬡`) in section headers and footer
- `▸` for key-value pairs inside ASCII boxes
- Amber color scheme in Mermaid diagrams (`fill:#f0a500`, `fill:#ffd966`)
- `➜` in trust assumption tables
- `💀` header for "Risk if Broken" column
- Dot leaders (`··········`) in threat scan status lines

**Hitlist categories**:
- 🔴 P0 — "Critical Sting Zone"
- 🟡 P1 — "Watch Zone"
- 🟢 P2 — "Low Pollen"

**Footer**: Always end with the honeycomb footer:
```
  ⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡
  🐝  Generated by Scoping Bee  •  [AUDITOR]  🍯
  ⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡⬡
```

**Sections NOT included in the report:**
- ~~Architectural Context (JSON)~~ → replaced by Flow Diagram
- ~~System Maps~~ → covered by Contract Inventory + Flow Diagram
- ~~Attack Surface Matrix~~ → internal analysis only, informs hitlist

---

<div align="center">

### ⬡ QUICK REFERENCE ⬡

</div>

## Quick Reference: Protocol Patterns

### Solidity
| Pattern | Key Risk Areas |
|---------|---------------|
| ERC4626 Vault | Share inflation, first depositor, rounding |
| Staking/Rewards | Reward index desync, claim pointer skips |
| AMM/DEX | Price manipulation, sandwich, IL calc |
| Lending | Oracle manipulation, liquidation thresholds |
| Bridge | Message replay, hash collision, relayer trust |
| Governance | Flash loan voting, timelock bypass |
| Proxy/Upgradeable | Storage collision, initialization |
| veToken/Escrow | Lock manipulation, decay calc, eligibility |

### Solana
| Pattern | Key Risk Areas |
|---------|---------------|
| Token Vault | Missing signer, PDA seed confusion |
| Staking | Reward calc overflow, stale oracle |
| DEX/AMM | Slippage bypass, pool drain via CPI |
| Lending | Liquidation oracle staleness |
| NFT Marketplace | Royalty bypass, listing replay |
| Bridge | Wormhole VAA replay, guardian trust |
| Governance | SPL-Gov quorum manipulation |
