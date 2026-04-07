---
name: scoping-bee
description: >-
  Perform structured pre-audit scoping for smart contract security audits
  (Solidity and Solana/Anchor). Analyzes a codebase to produce architectural
  context, system maps, attack surface enumeration, complexity scoring, and
  a time-estimated scope report with configurable auditor pace. Includes
  pre-scoping malware scan for untrusted codebases. Use when starting a new
  audit, scoping a contract, evaluating audit complexity, or preparing a
  scope document for a security engagement.
---

# 🐝 Scoping Bee

Systematic pre-audit scoping for smart contract security engagements.
Supports **Solidity** (Foundry/Hardhat) and **Solana/Anchor** (Rust) codebases.

Produces a structured scope report with configurable effort estimation that
feeds directly into deep audit methodologies (vector scanning,
threat interrogation, invariant extraction).

---

## Configuration

### Auditor Pace (Lines of Code per Day)

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

## Invocation

When the user asks to scope an audit:

1. Determine the **input type** (see Source Acquisition below)
2. If not a local directory, run the source fetcher to normalize the input
3. Detect language: Solidity (`.sol`) or Rust/Anchor (`.rs` with `Anchor.toml`)
4. Run **Phase 0: Malware Scan** first — ALWAYS
5. If clean, proceed through Phases 1–6
6. Output the final scope report as a markdown artifact using the template
   in [scope-report-template.md](references/scope-report-template.md)

---

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

## Phase 0: Malware Scan ⚠️ MANDATORY

**Run this BEFORE any other analysis.** Untrusted audit codebases can contain
malware targeting auditor machines.

```bash
bash <skill_dir>/scripts/malware_scan.sh <project_root>
```

The scan checks for:

### High Severity (BLOCK — do not proceed without user approval)
- **Shell command execution**: `forge script` with `--ffi`, Hardhat `exec`,
  npm `postinstall`/`preinstall` scripts that run code
- **Network exfiltration**: `curl`, `wget`, `fetch`, outbound HTTP in scripts
- **Obfuscated payloads**: Base64 encoded strings, hex-encoded shellcode
- **Suspicious binaries**: Compiled executables, `.so`/`.dylib` files
- **Symlinks**: Links pointing outside the repo (to `/etc`, `~/.ssh`, etc.)

### Medium Severity (WARN — flag for manual review)
- **FFI enabled in foundry.toml**: `ffi = true` allows Forge to shell out
- **Custom npm scripts**: Non-standard scripts in `package.json`
- **Assembly with external calls**: Inline assembly making syscalls
- **Hidden files**: Dotfiles that aren't standard config (`.env` is OK)

### Low Severity (INFO)
- `.env` files present (may contain secrets — don't commit)
- Large binary files (images, compiled artifacts)
- Git submodules pointing to unknown remotes

### Decision Logic

```
If HIGH severity findings → STOP. Report findings. Ask user to review.
If MEDIUM severity findings → WARN. Show findings. Ask user to confirm proceed.
If only LOW/NONE → Proceed automatically to Phase 1.
```

**Always show the malware scan summary** in the scope report regardless of
findings, so the user knows it was checked.

---

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
  ! -path "*/node_modules/*" ! -path "*/lib/*" | sort
```

**Rust/Anchor:**
```bash
find <programs_dir> -name "*.rs" \
  ! -path "*/tests/*" ! -path "*/test/*" \
  ! -path "*/target/*" ! -name "mod.rs" | sort
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

## Phase 2: Architectural Context Build

Produce the architectural context JSON — the most critical scoping output.

```json
{
  "protocol_type": "<DEX AMM | Lending | Staking | Vault | Bridge | DAO | NFT | Token>",
  "chain": "<EVM | Solana | Multi-chain>",
  "token_model": "<token flow mechanics>",
  "accounting_model": "<how balances/shares/rewards tracked>",
  "upgradeability_model": "<None | Proxy | Upgradeable Program>",
  "value_flow": ["<how value enters, flows, exits>"],
  "trust_boundaries": ["<who trusts whom, admin powers, external deps>"]
}
```

### Solana-Specific Context
For Anchor programs, also capture:
- **PDA derivation seeds** and bump management
- **Account validation** patterns (init, has_one, constraint)
- **CPI targets** (cross-program invocations)
- **Signer authority** model

---

## Phase 3: Contract-Level System Mapping

### Solidity Contracts
For each core contract, extract: entry points, state variables, roles,
external calls, delegatecalls, modifiers, events, key invariants.
(See full spec in scope-report-template.md)

### Solana/Anchor Programs
For each instruction, extract:
```json
{
  "instruction": "<name>",
  "accounts": ["<account: type, mutable?, signer?, PDA?>"],
  "args": ["<param: type>"],
  "access_control": "<who can call>",
  "cpi_calls": ["<program::function>"],
  "state_changes": ["<what accounts are modified>"],
  "key_validations": ["<constraint checks>"]
}
```

### Cross-Contract/Program Dependency Graph
Mermaid diagram showing call relationships and data flow.

---

## Phase 4: Attack Surface Enumeration

Use the language-appropriate checklist from
[attack-surfaces.md](references/attack-surfaces.md).

**Solidity**: 24 EVM attack surfaces
**Solana**: 18 Solana-specific attack surfaces

Mark each: `✅ SAFE` | `⚠️ INVESTIGATE` | `❌ EXPOSED` | `N/A`

---

## Phase 5: Complexity & Risk Estimation

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

---

## Phase 6: Scope Report Assembly

Use the template at [scope-report-template.md](references/scope-report-template.md).

Output as: `<protocol_name>_scope_report.md`

---

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
