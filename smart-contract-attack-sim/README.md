# Smart Contract Attack Simulator

CLI tool that analyzes Solidity smart contracts for vulnerabilities and generates executable attack simulations to prove exploitability.

## Features

- **Vulnerability Detection:**
  - Reentrancy attacks (CRITICAL)
  - Missing access control (HIGH)
  - Unprotected selfdestruct (CRITICAL)
  - Unchecked external calls (MEDIUM)
  - Integer overflow/underflow (for Solidity < 0.8.0)

- **Exploit Proof Generation:**
  - Generates Foundry test files that demonstrate attacks
  - Clear pass/fail output with gas costs
  - Severity ratings (Critical/High/Medium/Low)

## Installation

```bash
# Install dependencies
npm install

# Build the project
npm run build

# (Optional) Link globally
npm link
```

## Usage

### Analyze a Contract

```bash
# Using npm
npm run dev -- analyze <path-to-contract.sol>

# Or if linked globally
attack-sim analyze <path-to-contract.sol>

# Example
npm run dev -- analyze samples/VulnerableVault.sol
```

### Options

```
-o, --output <dir>      Output directory for exploit proofs (default: ./test/exploits)
-f, --format <format>   Output format: terminal or json (default: terminal)
--no-exploits           Skip exploit generation
-v, --verbose           Verbose output
--min-severity <level>  Minimum severity to report: CRITICAL|HIGH|MEDIUM|LOW
```

### JSON Output (for CI/CD)

```bash
npm run dev -- analyze samples/VulnerableVault.sol --format json > report.json
```

## Running Exploit Tests

### 1. Install Foundry

**Windows (PowerShell):**
```powershell
# Install foundryup
curl -L https://foundry.paradigm.xyz | bash

# Then run foundryup to install forge
foundryup
```

**Or download from:** https://getfoundry.sh

### 2. Install forge-std

```bash
cd smart-contract-attack-sim
forge install foundry-rs/forge-std --no-commit
```

### 3. Run the Exploit Tests

```bash
# Run all exploit tests
forge test

# Run specific exploit
forge test --match-test testReentrancyExploit -vvv

# Run with gas report
forge test --gas-report
```

## Example Output

```
╔═══════════════════════════════════════════════════════════╗
║     Smart Contract Attack Simulator v0.1.0                ║
║     Vulnerability Detection & Exploit Generation          ║
╚═══════════════════════════════════════════════════════════╝

📂 Analyzing: samples/VulnerableVault.sol

🔴 CRITICAL: Reentrancy vulnerability in withdraw()
   Location: Line 46 in withdraw()
   Contract: VulnerableVault
   Attack vector: External call (call) before state update (balances)

✅ Exploit proof generated: test/exploits/exploit_reentrancy_withdraw.t.sol
   Run: forge test --match-test testReentrancyExploit
   Expected result: Attacker drains funds via recursive calls
   Estimated gas cost: 250,000
```

## Project Structure

```
smart-contract-attack-sim/
├── src/
│   ├── cli.ts                    # CLI entry point
│   ├── analyzer.ts               # Main analysis logic
│   ├── vulnerability-detector.ts # Pattern matching
│   ├── exploit-generator.ts      # Generates Foundry tests
│   ├── types.ts                  # TypeScript types
│   └── utils/
│       ├── parser.ts             # Solidity AST parsing
│       └── reporter.ts           # Output formatting
├── samples/
│   ├── VulnerableVault.sol       # Sample vulnerable contract
│   └── SimpleReentrant.sol       # Minimal reentrancy example
├── test/
│   └── exploits/                 # Generated exploit tests
├── package.json
├── tsconfig.json
├── foundry.toml
└── README.md
```

## Detected Vulnerability Types

| Type | Severity | Description |
|------|----------|-------------|
| Reentrancy | CRITICAL | External call before state update |
| Unprotected Selfdestruct | CRITICAL | Anyone can destroy contract |
| Missing Access Control | HIGH | Sensitive functions without auth |
| Integer Overflow/Underflow | HIGH | Unchecked arithmetic (pre-0.8.0) |
| Unchecked External Call | MEDIUM | Return value not checked |

## Roadmap

- [ ] GitHub Actions integration
- [ ] Mainnet fork testing
- [ ] MEV simulation
- [ ] Web UI
- [ ] More vulnerability patterns (flash loans, oracle manipulation, etc.)

## License

MIT
