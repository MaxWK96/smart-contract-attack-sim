import * as parser from '@solidity-parser/parser';
import * as fs from 'fs';
import * as path from 'path';
import {
  ParsedContract,
  ContractInfo,
  FunctionInfo,
  StateVariableInfo,
  ModifierInfo,
  ParameterInfo,
} from '../types';

export function parseFile(filePath: string): { ast: any; source: string } {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`File not found: ${absolutePath}`);
  }

  const source = fs.readFileSync(absolutePath, 'utf-8');

  try {
    const ast = parser.parse(source, {
      loc: true,
      range: true,
      tolerant: true,
    });
    return { ast, source };
  } catch (error: any) {
    throw new Error(`Failed to parse Solidity file: ${error.message}`);
  }
}

export function extractContractInfo(ast: any): ParsedContract {
  const result: ParsedContract = {
    contracts: [],
    pragmaVersion: null,
    imports: [],
  };

  for (const node of ast.children || []) {
    if (node.type === 'PragmaDirective' && node.name === 'solidity') {
      result.pragmaVersion = node.value;
    }

    if (node.type === 'ImportDirective') {
      result.imports.push(node.path);
    }

    if (node.type === 'ContractDefinition') {
      const contractInfo = extractContract(node);
      result.contracts.push(contractInfo);
    }
  }

  return result;
}

function extractContract(node: any): ContractInfo {
  const contract: ContractInfo = {
    name: node.name,
    kind: node.kind, // 'contract', 'interface', 'library'
    baseContracts: (node.baseContracts || []).map((bc: any) => bc.baseName.namePath),
    functions: [],
    stateVariables: [],
    modifiers: [],
  };

  for (const subNode of node.subNodes || []) {
    if (subNode.type === 'FunctionDefinition') {
      contract.functions.push(extractFunction(subNode));
    }

    if (subNode.type === 'StateVariableDeclaration') {
      for (const variable of subNode.variables || []) {
        contract.stateVariables.push(extractStateVariable(variable, subNode));
      }
    }

    if (subNode.type === 'ModifierDefinition') {
      contract.modifiers.push(extractModifier(subNode));
    }
  }

  return contract;
}

function extractFunction(node: any): FunctionInfo {
  return {
    name: node.name || (node.isConstructor ? 'constructor' : node.isFallback ? 'fallback' : 'receive'),
    visibility: node.visibility || 'public',
    stateMutability: node.stateMutability || 'nonpayable',
    modifiers: (node.modifiers || []).map((m: any) => m.name),
    parameters: (node.parameters || []).map(extractParameter),
    body: node.body,
    line: node.loc?.start?.line || 0,
  };
}

function extractParameter(node: any): ParameterInfo {
  return {
    name: node.name || '',
    typeName: getTypeName(node.typeName),
  };
}

function extractStateVariable(variable: any, declaration: any): StateVariableInfo {
  return {
    name: variable.name,
    typeName: getTypeName(variable.typeName),
    visibility: variable.visibility || 'internal',
    line: declaration.loc?.start?.line || 0,
  };
}

function extractModifier(node: any): ModifierInfo {
  return {
    name: node.name,
    parameters: (node.parameters || []).map(extractParameter),
    line: node.loc?.start?.line || 0,
  };
}

function getTypeName(typeNode: any): string {
  if (!typeNode) return 'unknown';

  if (typeNode.type === 'ElementaryTypeName') {
    return typeNode.name;
  }

  if (typeNode.type === 'UserDefinedTypeName') {
    return typeNode.namePath;
  }

  if (typeNode.type === 'Mapping') {
    return `mapping(${getTypeName(typeNode.keyType)} => ${getTypeName(typeNode.valueType)})`;
  }

  if (typeNode.type === 'ArrayTypeName') {
    return `${getTypeName(typeNode.baseTypeName)}[]`;
  }

  return 'unknown';
}

export function findExternalCalls(body: any): ExternalCallInfo[] {
  const calls: ExternalCallInfo[] = [];

  function traverse(node: any, parentLine?: number) {
    if (!node) return;

    const currentLine = node.loc?.start?.line || parentLine;

    // Check for .call(), .send(), .transfer()
    if (node.type === 'FunctionCall') {
      let expr = node.expression;

      // Handle NameValueExpression (e.g., .call{value: x}(""))
      if (expr?.type === 'NameValueExpression') {
        expr = expr.expression;
      }

      if (expr?.type === 'MemberAccess') {
        const memberName = expr.memberName;

        if (['call', 'send', 'transfer', 'delegatecall', 'staticcall'].includes(memberName)) {
          calls.push({
            type: memberName,
            line: currentLine || 0,
            node: node,
            target: expr.expression,
          });
        }
      }
    }

    // Recursively traverse child nodes
    for (const key in node) {
      if (node[key] && typeof node[key] === 'object') {
        if (Array.isArray(node[key])) {
          for (const child of node[key]) {
            traverse(child, currentLine);
          }
        } else {
          traverse(node[key], currentLine);
        }
      }
    }
  }

  traverse(body);
  return calls;
}

export interface ExternalCallInfo {
  type: string;
  line: number;
  node: any;
  target: any;
}

export function findStateChanges(body: any): StateChangeInfo[] {
  const changes: StateChangeInfo[] = [];

  function traverse(node: any, parentLine?: number) {
    if (!node) return;

    const currentLine = node.loc?.start?.line || parentLine;

    // Assignment to state variable (identifier = value)
    if (node.type === 'ExpressionStatement' && node.expression?.type === 'BinaryOperation') {
      const op = node.expression.operator;
      if (['=', '+=', '-=', '*=', '/='].includes(op)) {
        const left = node.expression.left;
        if (left?.type === 'Identifier' || left?.type === 'IndexAccess') {
          changes.push({
            variableName: getVariableName(left),
            line: currentLine || 0,
            node: node,
          });
        }
      }
    }

    // Direct binary operation assignment
    if (node.type === 'BinaryOperation' && ['=', '+=', '-=', '*=', '/='].includes(node.operator)) {
      const left = node.left;
      if (left?.type === 'Identifier' || left?.type === 'IndexAccess') {
        changes.push({
          variableName: getVariableName(left),
          line: currentLine || 0,
          node: node,
        });
      }
    }

    // Recursively traverse
    for (const key in node) {
      if (node[key] && typeof node[key] === 'object') {
        if (Array.isArray(node[key])) {
          for (const child of node[key]) {
            traverse(child, currentLine);
          }
        } else {
          traverse(node[key], currentLine);
        }
      }
    }
  }

  traverse(body);
  return changes;
}

function getVariableName(node: any): string {
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'IndexAccess') {
    return getVariableName(node.base);
  }
  if (node.type === 'MemberAccess') {
    return `${getVariableName(node.expression)}.${node.memberName}`;
  }
  return 'unknown';
}

export interface StateChangeInfo {
  variableName: string;
  line: number;
  node: any;
}

export function getSourceLine(source: string, lineNumber: number): string {
  const lines = source.split('\n');
  return lines[lineNumber - 1] || '';
}
