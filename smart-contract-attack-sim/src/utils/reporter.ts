import chalk from 'chalk';
import { AnalysisReport, Vulnerability, ExploitProof, Severity } from '../types';

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  CRITICAL: chalk.red.bold,
  HIGH: chalk.red,
  MEDIUM: chalk.yellow,
  LOW: chalk.blue,
  INFO: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
  INFO: 'ℹ️',
};

export function printBanner(): void {
  console.log(chalk.cyan.bold(`
╔═══════════════════════════════════════════════════════════╗
║     Smart Contract Attack Simulator v0.1.0                ║
║     Vulnerability Detection & Exploit Generation          ║
╚═══════════════════════════════════════════════════════════╝
`));
}

export function printAnalyzing(filePath: string): void {
  console.log(chalk.cyan(`\n📂 Analyzing: ${chalk.white(filePath)}\n`));
}

export function printVulnerability(vuln: Vulnerability, index: number): void {
  const color = SEVERITY_COLORS[vuln.severity];
  const icon = SEVERITY_ICONS[vuln.severity];

  console.log(color(`${icon} ${vuln.severity}: ${vuln.title}`));
  console.log(chalk.gray(`   Location: Line ${vuln.location.line}${vuln.location.functionName ? ` in ${vuln.location.functionName}()` : ''}`));
  console.log(chalk.gray(`   Contract: ${vuln.location.contractName || 'Unknown'}`));
  console.log(chalk.white(`   Attack vector: ${vuln.attackVector}`));
  console.log(chalk.gray(`   ${vuln.description}`));
  console.log();
}

export function printExploitProof(proof: ExploitProof): void {
  console.log(chalk.green(`✅ Exploit proof generated: ${chalk.white(proof.testFilePath)}`));
  console.log(chalk.gray(`   Run: ${chalk.cyan('forge test --match-test ' + getTestName(proof))}`));
  console.log(chalk.gray(`   Expected result: ${proof.expectedResult}`));
  console.log(chalk.gray(`   Estimated gas cost: ${proof.estimatedGasCost.toLocaleString()}`));
  console.log();
}

function getTestName(proof: ExploitProof): string {
  const typeMap: Record<string, string> = {
    reentrancy: 'testReentrancyExploit',
    'integer-overflow': 'testOverflowExploit',
    'integer-underflow': 'testUnderflowExploit',
    'unprotected-selfdestruct': 'testSelfdestructExploit',
    'access-control': 'testAccessControlExploit',
    'unchecked-call': 'testUncheckedCallExploit',
  };
  return typeMap[proof.vulnerability.type] || 'testExploit';
}

export function printSummary(report: AnalysisReport): void {
  console.log(chalk.cyan.bold('═══════════════════════════════════════════════════════════'));
  console.log(chalk.cyan.bold('                        SUMMARY                            '));
  console.log(chalk.cyan.bold('═══════════════════════════════════════════════════════════'));
  console.log();

  console.log(chalk.white(`Contract: ${report.contractName || 'Unknown'}`));
  console.log(chalk.white(`File: ${report.filePath}`));
  console.log(chalk.white(`Solidity Version: ${report.solcVersion || 'Unknown'}`));
  console.log();

  console.log(chalk.white('Vulnerabilities Found:'));
  console.log(SEVERITY_COLORS.CRITICAL(`  🔴 Critical: ${report.summary.critical}`));
  console.log(SEVERITY_COLORS.HIGH(`  🟠 High:     ${report.summary.high}`));
  console.log(SEVERITY_COLORS.MEDIUM(`  🟡 Medium:   ${report.summary.medium}`));
  console.log(SEVERITY_COLORS.LOW(`  🔵 Low:      ${report.summary.low}`));
  console.log(chalk.white(`  ───────────────`));
  console.log(chalk.white.bold(`  Total:       ${report.summary.total}`));
  console.log();

  if (report.exploitProofs.length > 0) {
    console.log(chalk.green.bold(`✅ ${report.exploitProofs.length} exploit proof(s) generated`));
    console.log(chalk.gray(`   Run all exploits: ${chalk.cyan('forge test')}`));
  } else if (report.summary.total > 0) {
    console.log(chalk.yellow('⚠️  No exploit proofs generated (vulnerabilities may not be exploitable)'));
  } else {
    console.log(chalk.green('✅ No vulnerabilities detected!'));
  }

  console.log();
}

export function printError(message: string): void {
  console.log(chalk.red(`❌ Error: ${message}`));
}

export function printWarning(message: string): void {
  console.log(chalk.yellow(`⚠️  Warning: ${message}`));
}

export function printSuccess(message: string): void {
  console.log(chalk.green(`✅ ${message}`));
}

export function printInfo(message: string): void {
  console.log(chalk.cyan(`ℹ️  ${message}`));
}

export function formatJsonReport(report: AnalysisReport): string {
  return JSON.stringify(report, null, 2);
}

export function printDivider(): void {
  console.log(chalk.gray('───────────────────────────────────────────────────────────'));
}
