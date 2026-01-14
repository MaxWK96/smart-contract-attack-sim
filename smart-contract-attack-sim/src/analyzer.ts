import * as path from 'path';
import { parseFile, extractContractInfo } from './utils/parser';
import { detectVulnerabilities } from './vulnerability-detector';
import { generateExploitProofs } from './exploit-generator';
import { AnalysisReport, AnalyzerConfig, Vulnerability } from './types';

const DEFAULT_CONFIG: AnalyzerConfig = {
  verbose: false,
  outputFormat: 'terminal',
  generateExploits: true,
  outputDir: './test/exploits',
};

export async function analyzeContract(
  filePath: string,
  config: Partial<AnalyzerConfig> = {}
): Promise<AnalysisReport> {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  // Parse the Solidity file
  const { ast, source } = parseFile(filePath);

  // Extract contract information
  const parsed = extractContractInfo(ast);

  // Detect vulnerabilities
  const vulnerabilities = detectVulnerabilities(parsed);

  // Get the primary contract name (last contract in file, usually the main one)
  const primaryContract = parsed.contracts[parsed.contracts.length - 1];
  const contractName = primaryContract?.name || 'Unknown';

  // Generate exploit proofs
  let exploitProofs: ReturnType<typeof generateExploitProofs> = [];

  if (mergedConfig.generateExploits && vulnerabilities.some(v => v.exploitable)) {
    const absoluteFilePath = path.resolve(filePath);
    const outputDir = path.resolve(mergedConfig.outputDir);

    exploitProofs = generateExploitProofs(
      vulnerabilities,
      contractName,
      absoluteFilePath,
      outputDir
    );
  }

  // Build the report
  const report: AnalysisReport = {
    filePath: path.resolve(filePath),
    contractName,
    solcVersion: parsed.pragmaVersion,
    vulnerabilities,
    exploitProofs,
    summary: {
      critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
      medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      low: vulnerabilities.filter(v => v.severity === 'LOW').length,
      total: vulnerabilities.length,
    },
    timestamp: new Date().toISOString(),
  };

  return report;
}

export function filterVulnerabilities(
  vulnerabilities: Vulnerability[],
  minSeverity: string
): Vulnerability[] {
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const minIndex = severityOrder.indexOf(minSeverity.toUpperCase());

  if (minIndex === -1) return vulnerabilities;

  return vulnerabilities.filter(v => {
    const vulnIndex = severityOrder.indexOf(v.severity);
    return vulnIndex <= minIndex;
  });
}
