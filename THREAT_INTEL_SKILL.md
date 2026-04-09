---
name: threat-intel-scan
description: >-
  Comprehensive threat intelligence scanner for untrusted codebases.
  Detects malware, backdoors, supply chain attacks, phishing kits, obfuscated
  payloads, credential theft, crypto drainers, honeypot contracts, and all
  known classes of malicious code across Solidity, Rust, JavaScript, Python,
  Go, and infrastructure files. Use before any audit engagement to protect
  auditor machines and flag malicious intent.
---

# THREAT INTELLIGENCE SCAN — COMPREHENSIVE SKILL

**`━━━━⬡⬡⬡━━━━ THREAT INTEL METHODOLOGY ━━━━⬡⬡⬡━━━━`**

Deep, multi-phase threat intelligence scanner for **untrusted codebases**.
Run this BEFORE touching, building, testing, or auditing any code from an
external party. Covers **all known malicious code classes** across every
language and framework commonly seen in smart-contract audit engagements.

> **SANDBOX FIRST**: Always run inside an isolated environment (VM, Docker,
> cloud instance). Only move code to your local machine after a CLEAN verdict.

---

## INVOCATION

```
When the user asks to run a threat intel scan, or when a new codebase is
received for audit, execute ALL phases below against the target directory.
Report findings grouped by severity (HIGH > MEDIUM > LOW > INFO).
```

---

## SEVERITY DEFINITIONS

| Severity | Meaning | Action |
|----------|---------|--------|
| **CRITICAL** | Active malware, confirmed backdoor, known exploit kit | **BLOCK immediately. Do NOT proceed.** |
| **HIGH** | Strong malicious indicators, active exfiltration, obfuscated payloads | **BLOCK. Report findings. Require explicit user approval.** |
| **MEDIUM** | Suspicious patterns that could be legitimate but warrant review | **WARN. Show findings. Ask user to confirm proceed.** |
| **LOW** | Weak signals, informational indicators | **NOTE. Proceed automatically.** |
| **INFO** | Metadata and profiling information | **LOG. No action needed.** |

---

## PHASE 1: CODE EXECUTION & PERSISTENCE

Detect code that auto-executes, persists, or runs without user intent.

### 1.1 Auto-Execution Hooks (HIGH)
- **npm lifecycle scripts**: `postinstall`, `preinstall`, `prepare`, `prepublish`, `prepublishOnly`, `prepack`, `postpack`
- **Python setup hooks**: `setup.py` with `cmdclass`, `install` override, `develop` override
- **Python pyproject.toml**: `[tool.setuptools.cmdclass]` overrides
- **Makefile auto-targets**: `.DEFAULT`, `.PHONY` with network/exec commands
- **Cargo build scripts**: `build.rs` with `Command::new()`, `std::process::Command`
- **Gradle/Maven hooks**: `gradle.build` with `exec`, `ProcessBuilder`
- **Git hooks in repo**: `.git/hooks/`, `.husky/` with suspicious payloads
- **GitHub Actions**: `.github/workflows/*.yml` — check for `curl | bash`, encoded payloads, secret exfiltration
- **Docker entrypoints**: `ENTRYPOINT`, `CMD` in Dockerfiles with network/exec commands
- **Cron/systemd**: `crontab`, `.service` files, `launchd` plist, `at` jobs

### 1.2 Process Spawning & Shell Execution (HIGH)
- `child_process` (Node.js): `exec`, `execSync`, `spawn`, `spawnSync`, `fork`, `execFile`
- `subprocess` (Python): `Popen`, `call`, `check_output`, `run`, `getstatusoutput`
- `os.system`, `os.popen`, `os.exec*` (Python)
- `commands.getoutput` (Python 2)
- `std::process::Command` (Rust)
- `os/exec` (Go): `exec.Command`
- `Runtime.exec()` (Java)
- `system()`, `popen()` (C/C++)
- Forge FFI: `vm.ffi()` in Solidity test files
- `eval()`, `exec()`, `Function()`, `new Function()`, `setTimeout(string)`, `setInterval(string)`

### 1.3 Dynamic Code Loading (HIGH)
- `require()` with variable path (Node.js)
- `import()` dynamic imports with computed strings
- `importlib.import_module()` (Python)
- `__import__()` (Python)
- `dlopen`, `dlsym` (C/C++)
- `Assembly.Load`, `Activator.CreateInstance` (.NET)
- `Class.forName()` (Java)
- WebAssembly instantiation: `WebAssembly.instantiate`, `WebAssembly.compile`
- `vm.runInNewContext`, `vm.createContext` (Node.js)

---

## PHASE 2: NETWORK EXFILTRATION & C2

Detect outbound data transmission and command-and-control channels.

### 2.1 HTTP/HTTPS Outbound Calls (HIGH)
- `curl`, `wget`, `fetch()`, `XMLHttpRequest`, `sendBeacon`
- `http.get`, `https.get`, `http.request`, `https.request` (Node.js)
- `axios`, `got`, `node-fetch`, `superagent`, `request`, `undici`
- `requests`, `urllib`, `urllib3`, `httpx`, `aiohttp` (Python)
- `reqwest`, `hyper`, `ureq`, `surf` (Rust)
- `net/http` (Go)
- `HttpClient`, `WebClient` (.NET)
- `OkHttp`, `HttpURLConnection` (Java)

### 2.2 DNS-Based Exfiltration (HIGH)
- `dns.resolve`, `dns.lookup` with encoded data in subdomains
- `dig`, `nslookup`, `host` commands with data payloads
- DNS TXT record queries with base64 data
- DoH (DNS over HTTPS) requests

### 2.3 WebSocket & Real-Time Channels (MEDIUM)
- `WebSocket`, `ws://`, `wss://`
- `Socket.IO`, `socket.io-client`
- `MQTT`, `mqtt://`
- Server-Sent Events (`EventSource`)
- `WebRTC` data channels

### 2.4 Email/Messaging Exfiltration (HIGH)
- `nodemailer`, `sendgrid`, `mailgun`, `smtp`, `SMTP`
- `twilio`, `sns.publish`
- Slack/Discord webhook URLs
- Telegram bot API calls (`api.telegram.org`)

### 2.5 Cloud Storage Exfiltration (HIGH)
- AWS S3 `putObject`, `upload`
- GCS `storage.bucket().upload`
- Azure Blob `uploadBlockBlob`
- Firebase `database().ref().set`
- IPFS `ipfs.add`
- Pastebin/GitHub Gist API calls

### 2.6 Steganographic & Covert Channels (HIGH)
- Image pixel manipulation for data hiding
- Audio/video metadata embedding
- Unicode zero-width character encoding (`\u200b`, `\u200c`, `\u200d`, `\ufeff`)
- CSS `content` property with encoded data
- HTTP header-based exfiltration (`User-Agent`, `Cookie`, custom headers)

---

## PHASE 3: OBFUSCATION & ENCODING

Detect attempts to hide malicious intent through encoding and obfuscation.

### 3.1 Base64 Encoding (HIGH)
- Long base64 strings (>100 chars)
- `atob()`, `btoa()` (JavaScript)
- `base64.b64decode`, `base64.b64encode` (Python)
- `base64::decode`, `base64::encode` (Rust)
- `encoding/base64` (Go)
- Double/triple encoded base64

### 3.2 Hex Encoding (HIGH)
- Hex-encoded byte sequences: `\x??` patterns (>10 bytes)
- `Buffer.from(hex)`, `Buffer.from('...', 'hex')`
- `bytes.fromhex()` (Python)
- `hex::decode` (Rust)

### 3.3 String Obfuscation (HIGH)
- `String.fromCharCode()` with numeric arrays
- `String.fromCodePoint()` chains
- Character code concatenation: `chr()` chains (Python)
- String reversal: `.split('').reverse().join('')`
- ROT13 / Caesar cipher patterns
- XOR-based string deobfuscation loops
- Template literal injection with computed values

### 3.4 JavaScript Obfuscation (HIGH)
- Variable names: `_0x[a-f0-9]{4,}` patterns (js-obfuscator)
- `[]["filter"]["constructor"]` bracket notation for `Function`
- JSFuck patterns: `(![]+[])[+[]]`
- Packed code: `eval(function(p,a,c,k,e,d){`
- `unescape()`, `decodeURIComponent()` chains
- `document.write(unescape(...))`
- Computed property access: `window["ev"+"al"]`
- `Proxy` / `Reflect` abuse for hiding calls

### 3.5 Crypto Mining / Cryptojacking (HIGH)
- Known miners: `CoinHive`, `CryptoLoot`, `deepMiner`, `CoinImp`, `JSEcoin`, `WebMinePool`
- Mining algorithms: `cryptonight`, `equihash`, `ethash`, `randomx`
- Mining indicators: `stratum+tcp://`, `hashrate`, `nonce`, `getHashesPerSecond`
- Currency references in compute context: `monero`, `XMR` with WASM/worker patterns
- WebWorker-based mining: `new Worker()` with hash/mine/compute imports
- WASM modules for mining: `wasm.*mine`, `wasm.*hash`, `*.wasm` loading with compute loops

### 3.6 Unicode & Encoding Abuse (MEDIUM)
- Heavy HTML entity encoding: `&#x??;` sequences (>5 consecutive)
- Unicode escape sequences: `\u????` patterns (>5 consecutive)
- Right-to-left override characters (`\u202e`) — filename/display spoofing
- Homoglyph attacks (Cyrillic/Greek lookalikes for Latin chars)
- Invisible Unicode characters in identifiers
- UTF-7 encoded payloads

### 3.7 Serialization-Based Attacks (HIGH)
- Python `pickle.loads()`, `pickle.load()`, `cPickle`
- Java deserialization: `ObjectInputStream`, `readObject()`
- PHP `unserialize()`
- Ruby `Marshal.load()`
- YAML `!!python/object` (PyYAML unsafe load)
- `yaml.load()` without `Loader=SafeLoader`
- `JSON.parse()` with `reviver` doing code execution
- `msgpack` with custom deserializers

---

## PHASE 4: CREDENTIAL & SECRET THEFT

Detect attempts to steal credentials, keys, tokens, and secrets.

### 4.1 Hardcoded Secrets (HIGH)
- Private keys: `0x[a-fA-F0-9]{64}` (Ethereum), `[1-9A-HJ-NP-Za-km-z]{87,88}` (Solana)
- Mnemonics/seed phrases: 12/24 word BIP39 patterns
- API keys: `sk-`, `pk-`, `AKIA`, `AIza`, `ghp_`, `glpat-`, `xox[bpsa]-`
- JWT tokens: `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`
- AWS credentials: `AKIA[0-9A-Z]{16}`, `aws_secret_access_key`
- Database connection strings with embedded passwords
- `.pem`, `.key`, `.p12`, `.pfx` files in repo

### 4.2 Browser Storage Theft (HIGH)
- `document.cookie` — cookie access/exfiltration
- `localStorage.getItem()` — stored token theft
- `sessionStorage.getItem()` — session data theft
- `indexedDB` — stored database access
- `navigator.credentials` — credential manager access
- `PasswordCredential`, `FederatedCredential` — browser credential API

### 4.3 Clipboard Hijacking (HIGH)
- `navigator.clipboard.writeText()` — clipboard overwrite (address swap)
- `navigator.clipboard.readText()` — clipboard theft
- `document.execCommand('copy')` — legacy clipboard
- `oncopy`, `oncut`, `onpaste` event interception
- `clipboardData.setData()` — clipboard data injection

### 4.4 Keylogging & Input Capture (HIGH for capture+exfil, LOW for listeners alone)
- `addEventListener('keydown')`, `addEventListener('keyup')`, `addEventListener('keypress')`, `addEventListener('input')` — keyboard event listeners (LOW if standalone, HIGH if combined with network exfil)
- `onkeydown`, `onkeyup`, `onkeypress` HTML attributes
- `MutationObserver` on input fields
- `input` event listeners on password/credential fields
- Form `submit` event interception with data capture
- `beforeunload` with data exfiltration

### 4.5 Screen & Media Capture (HIGH)
- `navigator.mediaDevices.getUserMedia()` — camera/microphone
- `getDisplayMedia()` — screen capture
- `MediaRecorder` — recording streams
- `html2canvas`, `dom-to-image` — page screenshot
- `canvas.toDataURL()` — capturing rendered content

### 4.6 Environment Variable Harvesting (HIGH)
- `process.env` (Node.js) — accessing all env vars
- `os.environ` (Python) — environment access
- `std::env::vars()` (Rust) — reading env
- Reading `.env`, `.env.local`, `.env.production` files
- `dotenv` loading with exfiltration
- `printenv`, `env`, `set` command execution

---

## PHASE 5: FILESYSTEM & SYSTEM ACCESS

Detect unauthorized filesystem operations and system access.

### 5.1 Sensitive File Access (HIGH)
- Reading `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/config`
- Reading `~/.aws/credentials`, `~/.aws/config`
- Reading `~/.kube/config`
- Reading `~/.gnupg/`, `~/.gpg/`
- Reading `/etc/passwd`, `/etc/shadow`
- Reading `~/.bashrc`, `~/.zshrc`, `~/.profile` (credential harvesting)
- Reading browser profiles: `~/.config/google-chrome/`, `~/Library/Application Support/`
- Reading wallet files: `~/.config/solana/id.json`, `~/.ethereum/keystore/`
- Reading `~/.gitconfig`, `~/.netrc` (credential stores)

### 5.2 File System Manipulation (HIGH)
- Symlinks pointing outside repo (`readlink` check)
- Hard links to sensitive files
- Path traversal patterns: `../`, `..\\`, `%2e%2e/`
- Archive extraction with path traversal (zip slip)
- Temp directory abuse: writing to `/tmp/`, `os.tmpdir()`
- `/proc/self/` access (Linux process info)
- Device file access: `/dev/`, `\\.\`

### 5.3 Binary & Executable Files (HIGH)
- Compiled binaries: `.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.elf`
- Shellscripts in unexpected locations
- ELF/PE/Mach-O headers in non-binary files
- `.wasm` files (WebAssembly) — verify source
- `.class`, `.jar` (Java compiled)
- `.pyc`, `.pyo` (Python compiled)

### 5.4 File Permission Manipulation (HIGH)
- `chmod +x`, `chmod 777`
- `chown` commands
- `setuid`/`setgid` bits
- ACL manipulation
- `umask` changes

### 5.5 Sensitive Files in Repository (LOW–MEDIUM)
- `.env` files present (excluding `.env.example`, `.env.sample`) — may contain secrets
- `.env.local`, `.env.production`, `.env.staging` — environment-specific secrets
- Keypair/wallet references: files matching `(keypair|wallet|key).*\.(json|key|pem)`
- Anchor deploy scripts referencing keypair paths
- Large binary files (>1MB) in repo — unusual for source-only repos, verify content
- Files with double extensions (`.js.exe`, `.sol.sh`) — potential disguised executables
- Non-standard hidden files (exclude standard dotfiles: `.gitignore`, `.prettierrc`, `.eslintrc`, `.editorconfig`, `.npmrc`, `.nvmrc`, `.tool-versions`, `.browserslistrc`, `.babelrc`, `.solhint`, `.husky`, `.vscode`, `.idea`, `.DS_Store`)

---

## PHASE 6: HTML/PHISHING & WEB ATTACKS

Detect phishing kits, credential harvesting, and web-based attacks.

### 6.1 Phishing Forms (HIGH)
- `<form>` with `action=` pointing to external URLs
- `method="post"` forms with password/credit card/SSN fields
- Fake login pages mimicking known brands
- Form data intercepted before submission via JS
- Auto-submit forms (`form.submit()` on load)

### 6.2 Hidden/Invisible Elements (HIGH)
- Hidden iframes: `display:none`, `visibility:hidden`, `width:0/1`, `height:0/1`
- Off-screen positioned elements (`left:-9999px`)
- Zero-opacity overlays for clickjacking
- CSS `pointer-events:none` overlays
- Transparent full-page click interceptors

### 6.3 Redirect Attacks (MEDIUM)
- Meta refresh redirects: `<meta http-equiv="refresh">`
- `window.location` assignment to external URLs
- `document.location.replace()`
- `window.open()` to external URLs
- `history.pushState`/`replaceState` URL manipulation
- HTTP 3xx redirect chains
- `<base href>` hijacking

### 6.4 External Script & Resource Loading (MEDIUM)
- `<script src="https://...">` loading from external domains — verify all sources
- `<link rel="stylesheet" href="https://...">` — CSS-based exfiltration possible
- `<img src="https://...">` loading from external tracking domains
- Dynamic script injection: `document.createElement('script')` with external `src`
- Inline event handlers loading remote resources

### 6.5 Content Injection (HIGH)
- `document.write()` with external content
- `innerHTML` assignment from untrusted sources
- `outerHTML` manipulation
- `insertAdjacentHTML()` injection
- `DOMParser` with untrusted input
- Template injection: `${...}` in server-rendered HTML
- SVG `<foreignObject>` with embedded HTML/JS

### 6.6 Tracking & Surveillance (MEDIUM)
- 1x1 tracking pixels (`<img>` with `width=1 height=1`)
- Canvas fingerprinting: `canvas.toDataURL()`, `getImageData()`
- WebGL fingerprinting: `getExtension()`, `getParameter()`
- Audio fingerprinting: `AudioContext`, `createOscillator`
- Battery API: `navigator.getBattery()`
- Network Information API: `navigator.connection`
- Font enumeration fingerprinting
- `navigator.plugins`, `navigator.mimeTypes` enumeration

### 6.7 Brand Impersonation (HIGH)
- Asset filenames (`.ico`, `.png`, `.svg`, `.jpg`, `.gif`, `.webp`) matching known brands: MetaMask, Phantom, Uniswap, OpenSea, Coinbase, Binance, TrustWallet, Ledger, Trezor, Aave, Compound, Lido, PancakeSwap, SushiSwap, Curve, MakerDAO, dYdX, Yearn, 1inch
- HTML `<title>` matching brand names
- `manifest.json` with impersonated `name`/`short_name`
- Favicon references in HTML (`rel="icon"`, `rel="shortcut icon"`) — verify matches project branding (INFO)
- Open Graph / Twitter Card metadata with brand names
- App store metadata impersonation
- SSL certificate name spoofing references

---

## PHASE 7: SMART CONTRACT MALICIOUS PATTERNS (SOLIDITY)

Detect backdoors, drainers, honeypots, and exploitable patterns in Solidity.

### 7.1 Backdoor & Admin Abuse (HIGH)
- `selfdestruct` / `suicide` — contract destruction, drains all ETH
- Arbitrary `delegatecall` to user-supplied address — execute arbitrary code in contract context
- Low-level `.call{value:}` — verify target address and calldata (LOW)
- `transferOwnership` / `renounceOwnership` / `setOwner` / `changeAdmin` / `updateAdmin` — verify access control (LOW)
- Hidden `onlyOwner` functions that bypass intended logic
- Admin-only `mint()` without cap/supply limits
- `setFee()` / `setTax()` with no upper bound — rug pull via 100% fee
- `blacklist()`/`whitelist()` that blocks all transfers — honeypot
- `pause()` / `whenPaused` / `whenNotPaused` combined with `_mint` / `_burn` / `_transfer` — verify pause-gated minting/burning is intended (LOW)
- `pause()` without public `unpause()` — permanent freeze
- Hidden `withdraw()` / `emergencyWithdraw()` accessible to deployer
- Proxy admin upgrade to malicious implementation
- `setRouter` / `setPool` — swap target manipulation
- `excludeFromFee` — selective fee bypass for deployer

### 7.2 Honeypot Token Patterns (HIGH)
- `_transfer` with conditional revert for non-owner sells
- `maxTxAmount` that only applies to non-owner
- Buy tax = 0%, sell tax = 100% (configurable tax)
- Anti-bot that never disables
- `tradingEnabled` / `openTrading` that can be toggled off
- Approve/allowance manipulation that blocks DEX sells
- Balance manipulation in `balanceOf()` override
- Transfer to dead/null address on sell
- `cooldown` that applies differently to owner
- `maxWallet` that excludes deployer addresses
- Hidden fee redirect to deployer wallet

### 7.3 Reentrancy & Flash Loan (MEDIUM)
- State changes after external calls (CEI violation)
- Missing reentrancy guard on value-transferring functions
- `call{value:}` followed by state updates
- Cross-function reentrancy across multiple contracts
- Read-only reentrancy via view functions during callback
- Flash loan callback with price manipulation
- `flashLoan` receiver without proper validation

### 7.4 Token Approval Abuse (HIGH)
- `approve(MaxUint256)` — unlimited approval requests
- `setApprovalForAll(true)` — blanket NFT approval
- `increaseAllowance` without user-initiated action
- `permit()` / EIP-2612 gasless approval drain
- `Permit2` / `SignatureTransfer` abuse
- Multicall batching with hidden `transferFrom`
- `transferFrom` in fallback/receive function

### 7.5 Price & Oracle Manipulation (MEDIUM)
- Spot price calculation from pool reserves (manipulable)
- Single oracle source without TWAP
- Stale price feeds (`block.timestamp` checks missing)
- `getAmountsOut` / `getReserves` for price determination
- Missing slippage protection on swaps
- Flashloan-accessible oracle updates

### 7.6 Proxy & Upgrade Abuse (HIGH)
- `upgradeTo` / `upgradeToAndCall` without timelock
- Storage collision between proxy and implementation
- Uninitialized implementation contract (hijackable)
- Multiple inheritance with storage layout conflicts
- `UUPS` without `_authorizeUpgrade` protection
- Transparent proxy admin override
- Beacon proxy pointing to malicious implementation
- Diamond proxy with unguarded `diamondCut`
- CREATE2 with `selfdestruct` + redeploy (metamorphic contract)

### 7.7 Governance & Timelock Bypass (MEDIUM)
- Flash loan voting (borrow tokens, vote, return)
- Timelock with zero delay
- Emergency functions bypassing governance
- Quorum manipulation via token minting
- Proposal execution without sufficient delay
- Vote delegation to attacker-controlled address

### 7.8 Assembly & Low-Level Abuse (HIGH)
- Inline assembly with `sstore` to arbitrary slots
- Assembly `call` / `delegatecall` / `staticcall` bypassing Solidity checks
- `mstore` / `mload` with attacker-controlled offsets
- `create` / `create2` with runtime bytecode injection
- `extcodecopy` / `extcodesize` for EOA/contract detection
- `selfdestruct` in assembly (`ff` opcode)
- `returndatacopy` abuse
- Assembly-level `log0`-`log4` spoofing events

### 7.9 MEV & Front-Running Patterns (MEDIUM)
- Missing `deadline` parameter on swap functions
- No minimum output amount on DEX operations
- Commit-reveal schemes without proper implementation
- Auction/bid functions without front-running protection
- Sandwich-attackable price updates

### 7.10 Cross-Chain & Bridge Abuse (HIGH)
- Message replay across chains (missing chain ID)
- Hash collision in cross-chain message encoding
- Missing nonce in bridge messages
- Relayer trust assumptions without verification
- Fake proof submission
- Withdrawal replay attacks

### 7.11 Known Vulnerable Solidity Patterns (MEDIUM–HIGH)
- **`tx.origin` authentication** (HIGH): `require(tx.origin == ...)` — phishable, must use `msg.sender`
- **Unchecked call return values** (MEDIUM): `.call()` / `.send()` without `require` or `if` on success bool
- **Reentrancy via CEI violation** (MEDIUM): state changes after `.call{value:}` — verify checks-effects-interactions
- **Outdated Solidity version** (MEDIUM): `pragma solidity 0.[0-4].*` — known compiler bugs
- **Floating pragma** (LOW): `pragma solidity ^` — pin exact version for production
- **Unchecked arithmetic** (MEDIUM): Solidity < 0.8.x without SafeMath
- **Outdated OpenZeppelin** (MEDIUM): `@openzeppelin/contracts` < 4.x — known vulnerabilities
- **Outdated solc dependency** (MEDIUM): `solc` < 0.8 pinned in package.json
- **Old forge-std** (LOW): `.gitmodules` pinning forge-std v0.x — consider updating

### 7.12 Post-Signature & Approval Drain Patterns (HIGH)
- Unlimited token approval: `approve(MaxUint256)`, `approve(115792...)`, `setApprovalForAll`
- `increaseAllowance` without user-initiated flow
- Post-signature callback: `.then()` / `await` after `sign` calls executing transfers
- `signTypedData` chained with `.then()` executing state changes
- EIP-712 / Permit abuse: `DOMAIN_SEPARATOR`, `PERMIT_TYPEHASH`, `nonces[]`, `permitTransferFrom`
- Multicall + transferFrom batch drain: `multicall`/`aggregate`/`batch` combined with `transfer`/`transferFrom`

---

## PHASE 8: SMART CONTRACT MALICIOUS PATTERNS (RUST/SOLANA)

Detect Solana/Anchor-specific malicious patterns.

### 8.1 Account Validation Failures (HIGH)
- Missing `Signer` constraint on authority accounts
- `UncheckedAccount` / `AccountInfo` without validation
- Missing `has_one` constraints
- Missing `seeds` / PDA verification
- `remaining_accounts` without validation
- Missing `owner` check on deserialized accounts
- Account substitution attacks (wrong account type)
- Missing `is_writable` checks

### 8.2 PDA & Seed Manipulation (HIGH)
- PDA seed confusion (user-controlled seed components)
- Missing bump seed verification
- Seed collision attacks (crafted seeds)
- PDA authority bypass
- Cross-program PDA derivation mismatch

### 8.3 CPI & Invocation Abuse (HIGH)
- `invoke_signed` with user-controlled program ID
- CPI to arbitrary program
- Missing program ID verification in CPI
- Re-invocation attacks
- CPI with manipulated account ordering
- Privilege escalation via CPI signer seeds

### 8.4 Token & SOL Theft (HIGH)
- `transfer` SOL without owner verification
- SPL token `transfer` without authority check
- `close_account` draining lamports to attacker
- Token account closing without balance check
- Associated token account substitution
- Mint authority abuse

### 8.5 Initialization & State Attacks (HIGH)
- Reinitialization attack (missing `is_initialized` check)
- State account confusion (wrong discriminator)
- Account data truncation attacks
- Missing `rent_exempt` check
- Account reallocation abuse

---

## PHASE 9: PYTHON MALICIOUS PATTERNS

Detect Python-specific threats.

### 9.1 Code Execution (HIGH)
- `eval()`, `exec()`, `compile()` with user input
- `__import__()` with dynamic module names
- `importlib.import_module()` with external input
- `pickle.loads()` / `pickle.load()` — arbitrary code execution
- `yaml.load()` without `SafeLoader`
- `subprocess.*` with `shell=True`
- `os.system()`, `os.popen()`
- `ctypes` foreign function calls
- `ast.literal_eval()` is safe — but verify not confused with `eval()`

### 9.2 Setup Script Abuse (HIGH)
- `setup.py` with `cmdclass` overrides running arbitrary code
- `setup.py` importing from network at install time
- `__init__.py` in packages running code on import
- `conftest.py` in pytest running malicious fixtures
- `manage.py` commands with hidden execution

### 9.3 Dependency Confusion (HIGH)
- Internal package names clashing with public PyPI packages
- `--extra-index-url` pointing to attacker-controlled server
- `requirements.txt` with non-PyPI sources
- `setup.cfg` / `pyproject.toml` with custom index URLs
- Packages with `__init__.py` executing on import

---

## PHASE 10: GO MALICIOUS PATTERNS

Detect Go-specific threats.

### 10.1 Build-Time Execution (HIGH)
- `//go:generate` directives with suspicious commands
- `init()` functions with network calls or exec
- Build constraints hiding malicious code (`//go:build !prod`)
- CGo with embedded C executing shell commands

### 10.2 Runtime Threats (HIGH)
- `os/exec` with user-controlled arguments
- `plugin.Open()` — dynamic shared object loading
- `reflect` abuse for calling unexported methods
- `unsafe.Pointer` for memory manipulation
- `syscall` package direct system calls
- `net.Dial` with hardcoded C2 addresses

---

## PHASE 11: DEPENDENCY & SUPPLY CHAIN

Deep supply chain analysis across all ecosystems.

### 11.1 Known Malicious Packages (CRITICAL)
**npm (curated blocklist):**
- `event-stream`, `flatmap-stream`, `ua-parser-js` (compromised versions)
- `colors` (v1.4.1+), `faker` (v6.6.6)
- `node-ipc` (v10.1.1+), `peacenotwar`
- `coa` (compromised), `rc` (compromised)
- Typosquats: `crossenv`, `cross-env.js`, `d3.js`, `gruntcli`, `http-proxy.js`, `jquery.js`, `mongose`, `mysqljs`, `node-fabric`, `node-opencv`, `node-opensl`, `node-openssl`, `nodecaffe`, `nodefabric`, `nodemssql`, `noderequest`, `nodesass`, `nodesqlite`, `shadowsock`, `smb`, `sqliter`, `sqlserver`, `tkinter`, `babelcli`, `ffmepg`, `discordi.js`, `discord.jss`, `electorn`, `loadsh`, `lodashs`
- `@pnpm/exe`, `@pnpm/node`, `@pnpm/npm` (impersonation scoped packages)

**Python (curated blocklist):**
- `python3-dateutil`, `python-dateutil2`, `jeIlyfish` (homoglyph `l` vs `I`)
- `python-openssl`, `openssl-python`
- `setup-tools` (typosquat of `setuptools`)
- `request` (typosquat of `requests`)
- `beautifulsoup` (typosquat of `beautifulsoup4`)
- `urllib` (typosquat of `urllib3`)
- Any package with `__init__.py` executing `os.system` or `subprocess`

**Cargo/Rust:**
- Crate name typosquats of popular crates
- Crates with `build.rs` fetching from network

### 11.2 Suspicious Package Indicators (HIGH)
- Packages unrelated to smart contracts in audit repos:
  `puppeteer`, `playwright`, `selenium-webdriver`, `nightmare`,
  `nodemailer`, `sendgrid`, `mailgun`, `twilio`,
  `express`, `koa`, `fastify`, `hapi`,
  `socket.io`, `ws`, `mqtt`,
  `sharp`, `jimp`, `canvas`, `fluent-ffmpeg`,
  `ssh2`, `ftp`, `scp2`,
  `keylogger`, `screenshot-desktop`, `robotjs`

### 11.3 Lock File Manipulation (HIGH)
- Packages resolved from suspicious URLs: `pastebin`, `raw.githubusercontent`, `gist.github`, `bit.ly`, `tinyurl`, `t.co`
- Integrity hash mismatches between lock file and registry
- `resolved` URLs pointing to non-registry sources
- Lock file with entries not in `package.json`/`Cargo.toml`

### 11.4 Git-Based Dependencies (MEDIUM)
- `git+https://`, `git://`, `github:`, `bitbucket:`, `gitlab:` in manifests
- Git submodules pointing to suspicious origins
- Git dependencies pinned to branch (not tag/commit hash)
- Shallow clones hiding history

### 11.5 Custom Registries (MEDIUM)
- `.npmrc` with custom `registry=` URL
- `publishConfig.registry` in package.json
- `--registry` flag in npm scripts
- `.pip.conf` / `pip.ini` with custom `index-url`
- `~/.cargo/config.toml` with custom `[registries]`

### 11.6 Dependency Version Analysis (MEDIUM)
- OpenZeppelin < 4.x — known vulnerabilities
- solc < 0.8.x — unchecked arithmetic
- forge-std with outdated version
- Anchor < 0.28 — known vulnerabilities
- Dependencies with `*` or empty version (any version)
- `>=` without upper bound

### 11.7 npm Script Analysis (MEDIUM)
- Scripts with destructive commands: `rm`, `mv`, `chmod`, `chown`, `sudo`
- Scripts executing network commands: `curl`, `wget`, `node -e`, `bash`
- Scripts with encoded/obfuscated content
- Scripts piping curl to shell: `curl ... | sh`

### 11.8 npm Audit Integration (MEDIUM–HIGH)
- If `package-lock.json` exists and `npm` is available, run `npm audit --json`
- Critical vulnerabilities in npm dependencies → HIGH
- High vulnerabilities in npm dependencies → MEDIUM
- Dependency count check: >50 dependencies increases supply chain attack surface (LOW)

---

## PHASE 12: GIT & REPOSITORY PROFILING

Assess repository trustworthiness and detect manipulation.

### 12.1 Repository Age & History (MEDIUM)
- Repo < 7 days old — HIGH risk
- Repo < 30 days old — MEDIUM risk
- Only 1-3 commits — possible code dump, not organic development
- Single contributor — no peer review
- All commits in same hour — bulk dump pattern

### 12.2 History Manipulation (MEDIUM)
- Force push / rebase / amend evidence (>5 events in reflog)
- Commits authored by different names but same email
- Commits with future timestamps
- Commits with manipulated author dates
- Squashed history hiding development trail

### 12.3 Suspicious File Patterns (MEDIUM)
- Non-standard hidden files (excluding `.env`, `.gitignore`, IDE files, etc.)
- Files with double extensions (`.js.exe`, `.sol.sh`)
- Files with misleading extensions (binary content in `.js`)
- Files with extremely long names (>200 chars)
- Files with Unicode characters in names (homoglyph attack on filenames)

### 12.4 Git Metadata & Submodules (LOW–MEDIUM)
- Git submodules present — count them, verify remote origins are trusted
- No `.git` directory — cannot verify code provenance or development history (LOW)
- Author profile: log unique author count and total commit count (INFO)

### 12.5 Git Configuration Abuse (HIGH)
- `.gitattributes` with custom merge drivers executing code
- `.gitconfig` with aliases running arbitrary commands
- Git LFS pointing to attacker-controlled storage
- Git hooks with download/execution chains

---

## PHASE 13: INFRASTRUCTURE & CONFIGURATION

Detect threats in configuration and infrastructure files.

### 13.1 Docker & Container Threats (HIGH)
- `--privileged` flag in Docker commands
- Exposed secrets in `Dockerfile` (`ENV SECRET=...`)
- Suspicious base images (not from official repos)
- `COPY . .` including `.env` files
- Host filesystem mounts (`-v /:/host`)
- Network mode `--net=host`
- `docker.sock` mounted
- `SYS_PTRACE` / `SYS_ADMIN` capabilities

### 13.2 CI/CD Pipeline Threats (HIGH)
- GitHub Actions with `pull_request_target` + checkout of PR head (code injection)
- Actions using `${{ github.event.*.body }}` in `run:` (command injection)
- Third-party actions not pinned to SHA
- Workflow dispatch with `inputs` used unsanitized
- CircleCI/GitLab/Jenkins configs with secret exfiltration
- Self-hosted runners with persistent malware

### 13.3 Terraform/IaC Threats (MEDIUM)
- IAM policies with `*` permissions
- Security groups with `0.0.0.0/0` ingress
- S3 buckets with public access
- Hardcoded secrets in `.tf` files
- External module sources from untrusted repos

### 13.4 Foundry/Hardhat Configuration (MEDIUM)
- `foundry.toml` with `ffi = true` — Forge tests can execute arbitrary shell commands
- Hardhat config (`hardhat.config.*`) running external processes: `hre.run`, `exec()`, `execSync()`, `spawn()`
- Hardhat task files (`*.task.*`) with process spawning
- Custom Hardhat plugins loading external code
- Fork URL exposing private RPC endpoints with API keys
- Anchor deploy scripts referencing keypair/wallet `.json`/`.key`/`.pem` files

---

## PHASE 14: CRYPTOGRAPHIC ABUSE

Detect misuse of cryptographic primitives.

### 14.1 Weak/Broken Cryptography (MEDIUM)
- MD5, SHA1 for security-sensitive operations
- DES, 3DES, RC4 — weak ciphers
- ECB mode encryption
- Hardcoded encryption keys/IVs
- Math.random() / `rand()` for security purposes
- `block.timestamp` / `block.prevrandao` as sole randomness

### 14.2 Cryptographic Key Exposure (HIGH)
- Private keys in source code
- Wallet seed phrases / mnemonics in code
- Encryption keys in plaintext config
- Self-signed certificate generation and trust pinning
- Certificate pinning bypass attempts

### 14.3 Signature Manipulation (HIGH)
- Signature replay without nonce
- Missing chain ID in typed data signing (EIP-712)
- Malleable signatures (missing `v` normalization)
- Signature stripping/reuse
- `ecrecover` returning `address(0)` not checked

---

## PHASE 15: RUNTIME & ENVIRONMENT DETECTION

Detect code that behaves differently in different environments.

### 15.1 Sandbox Detection & Evasion (HIGH)
- Timing-based evasion (`Date.now()` checks, `performance.now()` deltas)
- VM/container detection (`navigator.webdriver`, `/proc/cpuinfo`)
- Debugger detection (`debugger` statement, anti-debugging loops)
- Environment checks: `NODE_ENV`, `DEBUG`, `CI`, `DOCKER`
- User-agent sniffing for bot detection
- Canvas/WebGL fingerprint comparison for VM detection
- `process.env.npm_lifecycle_event` to detect install vs runtime

### 15.2 Conditional Payload Activation (HIGH)
- Time-bomb: code activating after a specific date/block number
- IP/geolocation-based activation
- Balance-threshold activation (execute when wallet has enough)
- Domain/hostname checks for target discrimination
- Random activation (probabilistic payload delivery)
- Block number / epoch-based triggers

---

## PHASE 16: REACHABILITY & CALL GRAPH ANALYSIS

Verify if detected patterns are actually exploitable.

### 16.1 Orphan/Dead Code (MEDIUM)
- Source files not imported/required anywhere
- Functions defined but never called
- Exported functions with no external references
- Test/mock files in production paths

### 16.2 Entry Point Analysis (MEDIUM)
- Public/external functions with suspicious names:
  `withdraw`, `drain`, `sweep`, `emergencyWithdraw`, `execute`,
  `multicall`, `skim`, `backdoor`, `exploit`, `hack`, `steal`,
  `arbitrage`, `flashAttack`, `rugPull`, `honeypot`
- `fallback`/`receive` with non-trivial logic
- Constructor with side effects beyond initialization
- `initialize()` callable by anyone (not deployer-only)

### 16.3 Access Control Gaps (HIGH)
- Functions with no access control that modify critical state
- `onlyOwner` modifier with owner changeable by anyone
- Missing `initializer` modifier on proxy initialization
- Role-based access with public `grantRole`

---

## REPORT FORMAT

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT INTELLIGENCE SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL: [count]
HIGH:     [count]
MEDIUM:   [count]
LOW:      [count]
INFO:     [count]

── Scan Phases ──────────────────────────────────────────────
  Phase 1:  Code Execution & Persistence       [pass/fail]
  Phase 2:  Network Exfiltration & C2          [pass/fail]
  Phase 3:  Obfuscation & Encoding             [pass/fail]
  Phase 4:  Credential & Secret Theft          [pass/fail]
  Phase 5:  Filesystem & System Access         [pass/fail]
  Phase 6:  HTML/Phishing & Web Attacks        [pass/fail]
  Phase 7:  Smart Contract Malicious (Sol)     [pass/fail]
  Phase 8:  Smart Contract Malicious (Rust)    [pass/fail]
  Phase 9:  Python Malicious Patterns          [pass/fail]
  Phase 10: Go Malicious Patterns              [pass/fail]
  Phase 11: Dependency & Supply Chain          [pass/fail]
  Phase 12: Git & Repository Profiling         [pass/fail]
  Phase 13: Infrastructure & Configuration     [pass/fail]
  Phase 14: Cryptographic Abuse                [pass/fail]
  Phase 15: Runtime & Environment Detection    [pass/fail]
  Phase 16: Reachability & Call Graph          [pass/fail]

═══ [SEVERITY] FINDINGS ═══
  [icon] [category]: [detail with file:line reference]
  ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERDICT: [BLOCKED / WARNING / CLEAN]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Decision Logic

```
If CRITICAL findings  → BLOCK. Do NOT proceed. Report immediately.
If HIGH findings      → BLOCK. Report findings. Require explicit user approval.
If MEDIUM findings    → WARN. Show findings. Ask user to confirm proceed.
If only LOW/INFO      → CLEAN. Proceed automatically.
```

### Recommendations Section

After findings, always include:
1. **Immediate Actions**: What to do right now (isolate, delete, report)
2. **Verification Steps**: How to confirm if a finding is a true positive
3. **Mitigation**: Steps to safely proceed if user accepts the risk

---

## SCAN EXECUTION GUIDELINES

1. **File type coverage**: Scan ALL file types, not just code:
   - Source: `.sol`, `.rs`, `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`, `.py`, `.go`, `.java`, `.rb`, `.php`
   - Config: `.json`, `.toml`, `.yaml`, `.yml`, `.xml`, `.ini`, `.cfg`, `.conf`
   - Build: `Makefile`, `Dockerfile`, `docker-compose.*`, `Jenkinsfile`, `.gitlab-ci.yml`
   - Scripts: `.sh`, `.bash`, `.zsh`, `.bat`, `.ps1`, `.cmd`
   - Web: `.html`, `.htm`, `.svg`, `.php`, `.asp`, `.jsp`
   - Infra: `.tf`, `.tfvars`, `.hcl`

2. **Exclusion paths**: Skip these directories to avoid false positives:
   - `node_modules/`, `lib/` (Foundry), `target/` (Rust), `dist/`, `build/`
   - `.git/` (contents, not hooks)
   - `vendor/`, `__pycache__/`, `.tox/`, `.venv/`

3. **Context matters**: A pattern found in a test file is lower severity than in production code. Adjust severity accordingly but still report.

4. **Chained findings**: Multiple LOW findings in the same file that together form a malicious pattern should be escalated to HIGH. Example: `fetch()` + `document.cookie` + `btoa()` in the same file = data exfiltration chain.

5. **No false positive counts**: Do NOT report false positive numbers. Only report confirmed or suspected findings with their category and severity.

6. **Rate limiting**: For large codebases, limit per-file output (head -3 per pattern match) to avoid scan timeouts while still catching threats.
