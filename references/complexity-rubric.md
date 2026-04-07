# Complexity & Risk Scoring Rubric

Scoring system for estimating smart contract audit complexity and effort.
Applies to both **Solidity (EVM)** and **Rust/Anchor (Solana)** codebases.
Each metric is scored 1–4. Composite score = weighted average.

## Configurable Audit Pace

The effort formula uses a configurable **audit pace** (nSLOC reviewed per day):

```
Default: 350 nSLOC/day
```

| Pace | When to Use |
|------|------------|
| 400 nSLOC/day | Simple, well-documented, standard patterns |
| 350 nSLOC/day | **Default** — typical audit engagement |
| 300 nSLOC/day | High complexity, cross-contract flows, novel math |
| 250 nSLOC/day | Critical infrastructure, bridges, complex DeFi |

The user can override this at any time. When presenting estimates,
always state the pace used so they can recalculate.

---

## Metric 1: nSLOC (Weight: 25%)

Non-blank, non-comment source lines of code.

| Score | nSLOC Range | Description |
|-------|-------------|-------------|
| 1 | 0–100 | Small contract. Single responsibility. |
| 2 | 101–300 | Medium contract. Multiple functions, moderate state. |
| 3 | 301–600 | Large contract. Complex logic, many code paths. |
| 4 | 601+ | Very large. Likely needs decomposition or phased audit. |

---

## Metric 2: External Integration Risk (Weight: 25%)

Cross-contract calls, oracle dependencies, external protocol trust.

| Score | Criteria (Solidity) | Criteria (Solana) |
|-------|--------------------|-----------------|
| 1 | No external calls / standard transfers | No CPI, single program |
| 2 | Calls to trusted immutable libs (OZ) | CPI to SPL Token only |
| 3 | Calls to mutable contracts (strategies) | CPI to multiple programs, PDA signers |
| 4 | Untrusted addresses, multi-protocol | User-supplied program IDs, cross-chain |

### Red Flags (auto-bump to 3+)
- **Solidity**: `delegatecall`, user-supplied call targets, cross-contract reentrancy
- **Solana**: User-supplied program accounts, `invoke_signed` with complex seeds, `remaining_accounts` iteration

---

## Metric 3: State Coupling (Weight: 20%)

Number of state variables that must stay synchronized.

| Score | Criteria | Examples |
|-------|----------|---------|
| 1 | 1–3 simple state vars, independent | `owner`, `paused`, `totalSupply` |
| 2 | 4–8 state vars, some loosely coupled | Mapping + counter, balance + allowance |
| 3 | 9–15 state vars, multiple coupled invariants | Reward index + user snapshot + global counter must agree |
| 4 | 16+ state vars, complex cross-variable invariants | Epoch data + user cache + eligible supply + claim pointers |

### Red Flags (auto-bump to 3+)
- Sentinel values (0 means "unset", N+1 encoding)
- Monotonic pointer variables (claim pointers that can't go backward)
- Write-once flags that gate critical logic
- Cross-contract shared state

---

## Metric 4: Access Control Complexity (Weight: 15%)

Number and sophistication of roles and permissions.

| Score | Criteria | Examples |
|-------|----------|---------|
| 1 | Single role (owner) or no access control | Basic Ownable |
| 2 | 2 roles with clear separation | Owner + User |
| 3 | 3–4 roles with overlapping permissions | Owner + Admin + Operator + User |
| 4 | Role-based AC with delegation, timelock, multisig, governance | AccessControl + Timelock + Governor |

### Red Flags (auto-bump to 3+)
- Roles can be self-assigned
- No two-step ownership transfer
- Missing role checks on critical functions (inconsistent)
- `tx.origin` used for auth

---

## Metric 5: Upgradeability Risk (Weight: 15%)

Risk from upgrade patterns and mutability.

| Score | Criteria | Examples |
|-------|----------|---------|
| 1 | Immutable (no proxy, no admin-changeable state) | Pure contract, fixed parameters |
| 2 | Admin-mutable parameters with guardrails | Fee caps, timelocked changes |
| 3 | Proxy pattern with governance controls | UUPS + multisig + timelock |
| 4 | Proxy with EOA owner, or unconstrained mutability | TransparentProxy with single owner, unguarded setters |

### Red Flags (auto-bump to 3+)
- `selfdestruct` in implementation
- No storage gap in base contracts
- Uninitialized implementation contract
- Admin can change core protocol addresses without validation

---

## Composite Score Calculation

```
composite = (nSLOC × 0.25) + (extIntegration × 0.25) + (stateCoupling × 0.20) 
          + (accessControl × 0.15) + (upgradeability × 0.15)
```

### Risk Tier Mapping

| Composite Range | Tier | Color | Audit Approach |
|----------------|------|-------|----------------|
| 1.0 – 1.5 | LOW | 🟢 | Standard checklist review |
| 1.6 – 2.5 | MEDIUM | 🟡 | Pashov vector scan |
| 2.6 – 3.5 | HIGH | 🟠 | Full Nemesis interrogation |
| 3.6 – 4.0 | CRITICAL | 🔴 | Nemesis + invariant extraction + PoC |

---

## Effort Estimation Formula

Primary formula using configurable audit pace:

```
base_days = total_nSLOC / AUDIT_PACE
```

Default `AUDIT_PACE = 350` nSLOC/day. Users can adjust this value.

### Complexity Multipliers

Apply to base_days based on composite risk tier:

| Tier | Multiplier | Example: 1000 nSLOC @ 350/day |
|------|-----------|-------------------------------|
| LOW (1.0–1.5) | ×1.0 | 2.9 days → **3 days** |
| MEDIUM (1.6–2.5) | ×1.3 | 2.9 days → **3.7 days** |
| HIGH (2.6–3.5) | ×1.7 | 2.9 days → **4.9 days** |
| CRITICAL (3.6–4.0) | ×2.2 | 2.9 days → **6.3 days** |

### Quick Reference Table (at 350 nSLOC/day)

| nSLOC | Base Days | LOW | MEDIUM | HIGH | CRITICAL |
|-------|-----------|-----|--------|------|----------|
| 200 | 0.6 | 1 day | 1 day | 1 day | 1.5 days |
| 500 | 1.4 | 1.5 days | 2 days | 2.5 days | 3 days |
| 1000 | 2.9 | 3 days | 4 days | 5 days | 6.5 days |
| 2000 | 5.7 | 6 days | 7.5 days | 10 days | 12.5 days |
| 5000 | 14.3 | 14.5 days | 18.5 days | 24 days | 31.5 days |

### Quick Reference Table (at 300 nSLOC/day — high complexity)

| nSLOC | Base Days | LOW | MEDIUM | HIGH | CRITICAL |
|-------|-----------|-----|--------|------|----------|
| 200 | 0.7 | 1 day | 1 day | 1 day | 1.5 days |
| 500 | 1.7 | 2 days | 2 days | 3 days | 3.5 days |
| 1000 | 3.3 | 3.5 days | 4.5 days | 5.5 days | 7.5 days |
| 2000 | 6.7 | 7 days | 8.5 days | 11.5 days | 14.5 days |
| 5000 | 16.7 | 17 days | 21.5 days | 28.5 days | 36.5 days |

### Additional Effort Modifiers

Apply on top of the complexity-adjusted estimate:

| Factor | Modifier | When to Apply |
|--------|----------|---------------|
| Cross-contract/CPI interactions | +20% | Multiple contracts with shared state |
| Novel / non-standard patterns | +30% | Custom math, unusual architecture |
| Missing tests | +15% | No existing test suite |
| Missing documentation | +10% | No specs, no comments, no README |
| Multiple token types | +10% | Handles various ERC20/SPL behaviors |
| PoC requirement | +25% | Client requires exploit proofs |
| Native Solana (no Anchor) | +20% | Manual account parsing, no discriminators |

**Always show in the report:**
```
Audit pace: [N] nSLOC/day
Total nSLOC: [M]
Base days: [M ÷ N]
Complexity multiplier: [×X] (TIER)
Modifiers applied: [+Y%]
Final estimate: [Z] days
```

---

## Calibration Examples

Scores calibrated against real audits (at 350 nSLOC/day default):

| Protocol | Chain | nSLOC | Composite | Tier | Est. Days |
|----------|-------|-------|-----------|------|-----------|
| Simple ERC20 Token | EVM | 80 | 1.1 | LOW | 0.5 |
| Basic Staking | EVM | 250 | 2.0 | MEDIUM | 1 |
| VotingEscrow + Distributor | EVM | 1182 | 3.4 | HIGH | 5.5 |
| ERC4626 Vault + Strategy | EVM | 400 | 2.7 | HIGH | 2 |
| Cross-chain Bridge | EVM | 1200 | 3.8 | CRITICAL | 7.5 |
| SPL Token Vault | Solana | 300 | 2.0 | MEDIUM | 1 |
| Anchor Staking + Rewards | Solana | 800 | 2.8 | HIGH | 4 |
| Native Solana DEX | Solana | 1500 | 3.5 | HIGH | 7.5+ |
