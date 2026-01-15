export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ConfidenceLevel = 'confirmed' | 'likely' | 'theoretical';

export interface VulnerabilityLocation {
  line: number;
  column: number;
  functionName?: string;
  contractName?: string;
}

export interface VulnerabilityMetadata {
  environment: string;
  assumptions: string[];
  preconditions: string[];
  protectivePatterns: string[];
}

export interface FixSuggestion {
  name: string;
  description: string;
  vulnerableCode: string;
  fixedCode: string;
  gasImpact: string;
  pros: string[];
  cons: string[];
  recommended: boolean;
}

export interface AttackStep {
  step: number;
  title: string;
  description: string;
  codeSnippet?: string;
}

export interface EducationalContent {
  realWorldExample: {
    name: string;
    date: string;
    impact: string;
    description: string;
  };
  attackFlow: AttackStep[];
  keyLesson: string;
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
  confidence: ConfidenceLevel;
  confidenceScore: number;
  confidenceFactors: string[];
  metadata: VulnerabilityMetadata;
  fixSuggestions?: FixSuggestion[];
  educational?: EducationalContent;
}

export type VulnerabilityType =
  | 'reentrancy'
  | 'integer-overflow'
  | 'integer-underflow'
  | 'unprotected-selfdestruct'
  | 'access-control'
  | 'unchecked-call';

export interface SafetyCheck {
  category: string;
  pattern: string;
  status: 'safe' | 'vulnerable' | 'not_applicable';
  reason: string;
}

export interface AnalysisLimitations {
  covered: string[];
  notCovered: string[];
  disclaimer: string;
}

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
  safetyChecks: SafetyCheck[];
  limitations: AnalysisLimitations;
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
