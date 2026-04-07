# Attack Surface Checklist (EVM + Solana)

Comprehensive checklist for smart contract audit scoping. Each surface includes
trigger conditions — if any trigger matches, mark as `⚠️ INVESTIGATE`.

Use **Part A** for Solidity/EVM audits. Use **Part B** for Solana/Anchor audits.

---

# Part A: EVM (Solidity)

---

## 1. Reentrancy (Same-Contract)

**Trigger conditions:**
- External calls before state updates (violates CEI)
- Missing `nonReentrant` modifier on functions that transfer ETH/tokens
- Callback patterns (ERC721 `onERC721Received`, ERC1155, `receive()`)

**What to check:**
- State-then-external-call ordering in every function
- Whether `nonReentrant` covers all entry points
- ETH transfers via `call{}()` without reentrancy guard

---

## 2. Reentrancy (Cross-Contract)

**Trigger conditions:**
- Contract A calls Contract B, which calls back to Contract A (or C)
- Shared state across multiple contracts
- Vault → Strategy → Pool callback chains

**What to check:**
- Cross-contract state dependencies
- Whether reentrancy locks are shared across interacting contracts
- Read-only reentrancy (Balancer-style: state inconsistency exploited by
  reading intermediate state)

---

## 3. Delegatecall / Proxy Patterns

**Trigger conditions:**
- `delegatecall` used anywhere
- Proxy pattern (Transparent, UUPS, Beacon, Diamond)
- `selfdestruct` in implementation

**What to check:**
- Storage layout compatibility between proxy and implementation
- Initialization vs constructor (uninitializable implementations)
- Function selector clashes (Diamond pattern)
- `selfdestruct` or `delegatecall` in implementation that can brick proxy

---

## 4. Authorization Bypass

**Trigger conditions:**
- Multiple roles with different permissions
- Missing access control on state-changing functions
- `tx.origin` usage
- Inconsistent modifier application across similar functions

**What to check:**
- Every `external`/`public` function has appropriate access control
- Privilege escalation paths (can user reach admin functions?)
- Modifier consistency: if `functionA` has `onlyOwner`, does the similar
  `functionB` also have it?
- `msg.sender` vs `tx.origin` confusion

---

## 5. ERC20 Non-Standard Behavior

**Trigger conditions:**
- Protocol accepts arbitrary ERC20 tokens
- No whitelist of supported tokens
- Comments mentioning "fee-on-transfer" or "rebasing"

**What to check:**
- Fee-on-transfer tokens: actual received amount != transfer amount
- Rebasing tokens: balance changes without transfer
- Missing return values: some tokens don't return `bool` on `transfer`
- Tokens with `decimals != 18`
- Tokens that revert on zero-amount transfer
- Tokens with 2 address variants (e.g., TUSD)
- Upgradeable tokens that can change behavior

---

## 6. Oracle Manipulation

**Trigger conditions:**
- On-chain price feeds (Chainlink, TWAP, spot price)
- Calculations using token reserves or balances as prices
- Liquidation logic based on price thresholds

**What to check:**
- Spot price usage (manipulable in same TX via flash loans)
- TWAP window length (too short = manipulable)
- Stale oracle data (no freshness check on Chainlink `updatedAt`)
- Oracle decimals mismatch
- Circuit breaker absence (oracle returns 0 or extreme values)
- Multi-oracle inconsistency

---

## 7. Precision Loss / Rounding

**Trigger conditions:**
- Division operations (especially `a * b / c` patterns)
- Share/rate calculations
- Reward distribution math
- Tokens with different decimal counts interacting

**What to check:**
- Division before multiplication (precision loss)
- Rounding direction: does it favor protocol or user? (should favor protocol)
- Dust accumulation over many operations
- Decimal normalization when mixing tokens with different decimals
- Phantom overflow in intermediate calculations

---

## 8. Share Inflation / First Depositor

**Trigger conditions:**
- ERC4626 vault or any share-based accounting
- `totalAssets() / totalSupply()` ratio used for share price
- No minimum deposit / dead shares mechanism

**What to check:**
- First depositor can inflate share price by donating to vault
- Subsequent depositors get 0 shares due to rounding
- Presence of virtual shares/assets offset (OZ mitigation)
- Minimum initial deposit requirement

---

## 9. Flash Loan Vectors

**Trigger conditions:**
- Governance/voting based on token balance
- Price calculations using current reserves
- Any single-transaction balance check

**What to check:**
- Can balances be inflated within a single TX to manipulate protocol?
- Voting power from current balance (not time-weighted)
- Collateral value from spot price
- Lock time requirements that prevent same-TX deposit+withdraw

---

## 10. Timestamp / Block Dependency

**Trigger conditions:**
- `block.timestamp` or `block.number` used for critical logic
- Time-based rewards, vesting, or unlocking
- Epoch/period calculations

**What to check:**
- Miner manipulation window (~15 seconds)
- Off-by-one in period boundaries
- Epoch alignment assumptions (week boundaries, etc.)
- `block.timestamp` monotonicity assumptions across chains
- L2-specific timestamp behavior

---

## 11. Unchecked Low-Level Calls

**Trigger conditions:**
- `call()`, `delegatecall()`, `staticcall()` usage
- Assembly blocks with external calls
- `address.send()` or `address.transfer()`

**What to check:**
- Return value checked on all low-level calls
- Gas stipend limitations (`transfer` = 2300 gas, fails with proxy wallets)
- Calldata correctness in `abi.encodeWithSelector` / `abi.encode`

---

## 12. Storage Packing Collisions

**Trigger conditions:**
- Inline assembly that reads/writes storage
- Proxy patterns with inherited storage
- Tightly packed structs

**What to check:**
- Storage slot calculations in assembly
- Variable ordering across inherited contracts
- Struct packing assumptions (Solidity rules)

---

## 13. Gas Griefing / DoS

**Trigger conditions:**
- Loops over dynamic arrays
- External calls in loops
- User-influenced iteration counts
- `push`/`pop` on storage arrays

**What to check:**
- Unbounded loops (user can grow array to make function exceed gas limit)
- Reverting external calls in loops (one failure blocks all)
- Batch operations without gas limits
- Block gas limit constraints on critical functions

---

## 14. Reward Index Desynchronization

**Trigger conditions:**
- Reward distribution using accumulator pattern (`rewardPerToken`)
- Multiple reward tokens
- Epoch-based or streaming rewards
- Cross-contract reward sources

**What to check:**
- Checkpoint timing: is reward index updated before balance changes?
- Numerator/denominator source mismatch (global vs eligible vs snapshot)
- Reward pointer manipulation (skip/replay attack)
- Staking after reward accrual but before distribution

---

## 15. Signature Replay / EIP-712

**Trigger conditions:**
- `ecrecover` usage
- EIP-2612 permit
- Gasless transactions / meta-transactions
- Off-chain signed messages

**What to check:**
- Nonce management (prevent replay)
- Chain ID in domain separator (prevent cross-chain replay)
- `ecrecover` returns `address(0)` on invalid signature (must check)
- EIP-712 domain separator correctness
- Signature malleability (s-value range check)

---

## 16. Front-Running / MEV

**Trigger conditions:**
- Slippage-sensitive operations
- First-come-first-served mechanisms
- Commit-reveal schemes
- Admin parameter changes

**What to check:**
- Slippage protection on swaps/deposits/withdrawals
- Commit-reveal for sensitive actions
- Frontrunnable initialization
- Admin functions that change rates/params without timelock

---

## 17. Integer Overflow (Unchecked Blocks)

**Trigger conditions:**
- `unchecked { }` blocks
- Solidity < 0.8.0 (no built-in overflow checks)
- Assembly arithmetic

**What to check:**
- Every `unchecked` block: can values realistically overflow?
- Casting between types (uint256 → uint128, int → uint)
- Negation of `type(int256).min`
- Assembly arithmetic (no automatic checks)

---

## 18. Initialization / Constructor Issues

**Trigger conditions:**
- `initialize()` functions (proxy pattern)
- `constructor` in upgradeable contracts
- Missing initialization checks

**What to check:**
- Can `initialize()` be called multiple times?
- Is the implementation contract initialized? (prevent takeover)
- Are all state variables properly set during initialization?
- `initializer` modifier present and correct

---

## 19. Self-Destruct / Forced ETH

**Trigger conditions:**
- `selfdestruct` in any reachable code
- `address(this).balance` used in logic
- ETH accounting based on balance tracking

**What to check:**
- Forced ETH via `selfdestruct` breaks balance accounting
- `address(this).balance` ≠ tracked deposits
- Missing `receive()` / `fallback()` revert guard

---

## 20. Cross-Chain / Bridge Issues

**Trigger conditions:**
- Multi-chain deployment
- Bridge contracts or message passing (LayerZero, CCIP, Wormhole)
- Chain-specific behavior dependencies

**What to check:**
- Message replay across chains
- Relayer trust assumptions
- Chain-specific opcodes (`PUSH0`, `PREVRANDAO`, `SELFDESTRUCT`)
- Different gas costs / block times affecting logic
- Sequencer downtime on L2s (Chainlink sequencer uptime feed)

---

## 21. Access Control on Self-Destruct / Pause

**Trigger conditions:**
- Pausable contracts
- Emergency functions
- Kill switches

**What to check:**
- Can pause brick user funds permanently?
- Is there an unpause path if owner is compromised?
- Emergency withdrawal exists for users?
- Timelock on destructive admin functions?

---

## 22. ERC721/ERC1155 Callback Vectors

**Trigger conditions:**
- NFT minting/transferring
- `onERC721Received` / `onERC1155Received` callbacks
- `safeMint` / `safeTransferFrom`

**What to check:**
- Reentrancy via callback
- State modifications between mint and callback
- Arbitrary code execution in receiver contract

---

## 23. Governance / Voting Manipulation

**Trigger conditions:**
- On-chain governance
- Token-weighted voting
- Quorum requirements
- Proposal execution

**What to check:**
- Flash loan voting (borrow → vote → return)
- Vote buying / dark DAOs
- Quorum manipulation
- Proposal execution can be front-run
- Timelock bypass paths

---

## 24. Token Approval / Allowance Issues

**Trigger conditions:**
- `approve` / `increaseAllowance` patterns
- Infinite approvals
- Approval race conditions

**What to check:**
- Front-running `approve` (classic ERC20 race condition)
- Infinite approval to untrusted contracts
- `permit` + `transferFrom` interaction
- Dangling approvals after contract upgrade

---
---

# Part B: Solana (Rust / Anchor)

## S1. Missing Signer Check

**Trigger conditions:**
- Instruction accepts authority/admin accounts
- Account not marked `Signer` in Anchor `#[account]` struct
- Native Solana: missing `AccountInfo.is_signer` check

**What to check:**
- Can any account impersonate the authority?
- Is signer validation enforced before state mutation?
- Multi-signer scenarios: are ALL required signers checked?

---

## S2. Missing Owner / Program Check

**Trigger conditions:**
- Instruction reads data from accounts it doesn't own
- Passing arbitrary program-owned accounts
- No `owner` constraint in Anchor

**What to check:**
- Account `.owner == expected_program_id` verified
- Preventing injection of fake accounts owned by attacker's program
- SPL Token accounts validated against Token program ownership

---

## S3. Account Data Matching (Type Cosplay)

**Trigger conditions:**
- Multiple account types with same structure
- No discriminator validation
- Native Solana without Anchor's auto-discriminator

**What to check:**
- Can a Vault account be passed where a User account is expected?
- Anchor 8-byte discriminator present and checked
- Native programs: manual discriminator/tag validation

---

## S4. PDA Seed Confusion / Substitution

**Trigger conditions:**
- PDA derived from user-controlled seeds
- Multiple PDAs with overlapping seed patterns
- Missing bump seed validation

**What to check:**
- Seed uniqueness: can different inputs produce the same PDA?
- Canonical bump used (Anchor `bump` constraint)
- Variable-length seeds without delimiters (seed grinding)
- User can substitute one PDA for another

---

## S5. Missing Account Validation (has_one / constraint)

**Trigger conditions:**
- Accounts passed to instruction without relationship verification
- Missing `has_one` constraints in Anchor
- Account fields not cross-referenced

**What to check:**
- Vault.owner == signer (ownership links)
- Token account.mint == expected mint
- All relational invariants between accounts enforced

---

## S6. Arithmetic Overflow / Underflow

**Trigger conditions:**
- Rust integer arithmetic (default wraps in release builds)
- `checked_add/sub/mul/div` not used
- Large token amounts with multiplication

**What to check:**
- All arithmetic uses `checked_*` or Anchor's overflow protection
- `u64` overflow on token amounts (max ~18.4 quintillion)
- Intermediate multiplication overflow before division
- Casting between types (`u128` → `u64`, `i64` → `u64`)

---

## S7. CPI (Cross-Program Invocation) Exploits

**Trigger conditions:**
- Invoking other programs via `invoke` or `invoke_signed`
- Passing PDAs as signers to CPIs
- Calling Token program or System program

**What to check:**
- Is the target program ID hardcoded or user-supplied?
- Can attacker substitute a malicious program?
- PDA signer seeds correct for `invoke_signed`
- Account permissions (writable, signer) correct in CPI call

---

## S8. Reinitialization

**Trigger conditions:**
- `init` constraint in Anchor
- Custom initialization functions
- Account state reset patterns

**What to check:**
- Can `init` instruction be called twice? (Anchor prevents, but check `init_if_needed`)
- `init_if_needed` — attacker can front-run initialization
- Is there a `is_initialized` boolean checked and set?
- Closing and re-creating accounts to reset state

---

## S9. Closing Accounts Improperly

**Trigger conditions:**
- Account closure logic (zeroing lamports, transferring rent)
- `close` constraint in Anchor
- Manual account closing

**What to check:**
- Is account data zeroed after closing? (prevents revival attack)
- Lamports transferred to correct recipient?
- Can closed account be passed to other instructions before TX ends?
- Revival attack: refunding lamports to closed account in same TX

---

## S10. Rent Exemption Issues

**Trigger conditions:**
- Account creation with specific sizes
- Dynamic account resizing (`realloc`)
- Minimum balance assumptions

**What to check:**
- Account allocated with enough space for data + discriminator
- Rent-exempt minimum balance maintained
- `realloc` increases rent requirement appropriately
- System program invoked correctly for account creation

---

## S11. Token Account Validation

**Trigger conditions:**
- SPL Token / Token-2022 interactions
- Mint, transfer, burn operations
- Associated Token Accounts (ATAs)

**What to check:**
- Token account mint matches expected mint
- Token account authority matches expected authority
- ATA derivation is correct
- Token-2022 extensions (transfer fees, confidential transfers) handled

---

## S12. Oracle Staleness (Solana)

**Trigger conditions:**
- Pyth, Switchboard, or custom oracle usage
- Price-dependent logic (liquidation, swaps)

**What to check:**
- Oracle staleness check (`slot` or `publish_time` freshness)
- Confidence interval validation (Pyth `conf`)
- Oracle account ownership validation
- Fallback when oracle is unavailable

---

## S13. Duplicate Accounts

**Trigger conditions:**
- Instruction accepts multiple accounts of same type
- Source/destination patterns
- Multi-party instructions

**What to check:**
- Can the same account be passed as both source and destination?
- Duplicate mutable account references (Solana prevents, but logical bugs)
- Self-transfer creating/destroying tokens

---

## S14. Missing Instruction Ordering / Atomicity

**Trigger conditions:**
- Multi-instruction workflows (stake → claim → unstake)
- State flags that gate subsequent instructions
- Time/slot-dependent logic

**What to check:**
- Can instructions be reordered to bypass checks?
- Flash loan equivalents: borrow → use → repay in one TX
- State consistency between instructions within same TX

---

## S15. Remaining Accounts Exploitation

**Trigger conditions:**
- `ctx.remaining_accounts` used in Anchor
- Dynamic account lists
- Flexible multi-account patterns

**What to check:**
- Are remaining accounts validated (owner, signer, type)?
- Can attacker inject extra accounts to manipulate logic?
- Iteration over remaining accounts properly bounded

---

## S16. Program Upgrade Authority

**Trigger conditions:**
- Upgradeable BPF programs
- Authority management
- Multi-sig upgrade patterns

**What to check:**
- Who holds upgrade authority? (EOA vs multisig)
- Can authority be changed? By whom?
- Is program frozen/non-upgradeable when it should be?
- Upgrade authority = None means immutable

---

## S17. Lamport Manipulation

**Trigger conditions:**
- Logic based on account lamport balance
- Reward/fee distribution based on SOL balance
- Minimum stake requirements

**What to check:**
- Anyone can send lamports to any account (like forced ETH on EVM)
- Balance-based logic can be manipulated
- Rent-exempt balance confused with actual deposits

---

## S18. Clock / Slot Dependency

**Trigger conditions:**
- `Clock::get()` for time-based logic
- Slot-based calculations
- Epoch-dependent operations

**What to check:**
- Clock can drift on validators
- Slot times are not constant (~400ms average but variable)
- `unix_timestamp` from Clock sysvar vs slot number
- Epoch length assumptions

