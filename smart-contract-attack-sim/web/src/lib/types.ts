export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface VulnerabilityLocation {
  line: number;
  column: number;
  functionName?: string;
  contractName?: string;
}

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  title: string;
  description: string;
  location: VulnerabilityLocation;
  attackVector: string;
  recommendation: string;
  exploitable: boolean;
}

export type VulnerabilityType =
  | 'reentrancy'
  | 'integer-overflow'
  | 'integer-underflow'
  | 'unprotected-selfdestruct'
  | 'access-control'
  | 'unchecked-call';

export interface AnalysisResult {
  contractName: string;
  solcVersion: string | null;
  vulnerabilities: Vulnerability[];
  exploitCode: string | null;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export interface ContractInfo {
  name: string;
  kind: string;
  baseContracts: string[];
  functions: FunctionInfo[];
  stateVariables: StateVariableInfo[];
  modifiers: ModifierInfo[];
}

export interface FunctionInfo {
  name: string;
  visibility: string;
  stateMutability: string;
  modifiers: string[];
  parameters: ParameterInfo[];
  body: unknown;
  line: number;
}

export interface ParameterInfo {
  name: string;
  typeName: string;
}

export interface StateVariableInfo {
  name: string;
  typeName: string;
  visibility: string;
  line: number;
}

export interface ModifierInfo {
  name: string;
  parameters: ParameterInfo[];
  line: number;
}

export interface ParsedContract {
  contracts: ContractInfo[];
  pragmaVersion: string | null;
  imports: string[];
}
