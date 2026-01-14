#!/usr/bin/env node

import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import chalk from 'chalk';
import {
  printBanner,
  printAnalyzing,
  printVulnerability,
  printExploitProof,
  printSummary,
  printError,
  printSuccess,
  printInfo,
  printDivider,
  formatJsonReport,
} from './utils/reporter';
import { analyzeContract } from './analyzer';

const program = new Command();

program
  .name('attack-sim')
  .description('Smart Contract Attack Simulator - Vulnerability Detection & Exploit Generation')
  .version('0.1.0')
  .addHelpText('after', `
${chalk.cyan('Examples:')}
  $ attack-sim analyze MyContract.sol
  $ attack-sim analyze MyContract.sol --format json > report.json
  $ attack-sim analyze MyContract.sol --min-severity HIGH
  $ attack-sim analyze MyContract.sol --no-exploits
  $ attack-sim init

${chalk.cyan('Exit Codes:')}
  0  No vulnerabilities found
  1  Low severity vulnerabilities found
  2  Medium severity vulnerabilities found
  3  High severity vulnerabilities found
  4  Critical severity vulnerabilities found

${chalk.cyan('Vulnerability Types Detected:')}
  - Reentrancy attacks (CRITICAL)
  - Missing access control (HIGH)
  - Integer overflow/underflow (HIGH)
  - Unprotected selfdestruct (CRITICAL)
  - Unchecked external calls (MEDIUM)

${chalk.cyan('More Info:')}
  GitHub: https://github.com/MaxWK96/smart-contract-attack-sim
`);

program
  .command('analyze')
  .description('Analyze a Solidity contract for vulnerabilities and generate exploit proofs')
  .argument('<file>', 'Path to Solidity file (.sol)')
  .option('-o, --output <dir>', 'Output directory for generated exploit tests', './test/exploits')
  .option('-f, --format <format>', 'Output format: terminal (colored) or json (for CI/CD)', 'terminal')
  .option('--no-exploits', 'Skip generating Foundry exploit test files')
  .option('-v, --verbose', 'Show detailed error messages and stack traces')
  .option('--min-severity <level>', 'Minimum severity to report: CRITICAL, HIGH, MEDIUM, or LOW', 'LOW')
  .addHelpText('after', `
${chalk.cyan('Examples:')}
  $ attack-sim analyze contracts/Vault.sol
  $ attack-sim analyze contracts/Vault.sol -f json > report.json
  $ attack-sim analyze contracts/Vault.sol --min-severity HIGH --no-exploits

${chalk.cyan('After Analysis:')}
  Run generated exploit tests with: ${chalk.yellow('forge test --match-test Exploit')}
`)
  .action(async (file: string, options) => {
    try {
      // Resolve the file path
      const filePath = path.resolve(file);

      // Check if file exists
      if (!fs.existsSync(filePath)) {
        printError(`File not found: ${filePath}`);
        process.exit(1);
      }

      // Check if it's a .sol file
      if (!filePath.endsWith('.sol')) {
        printError('File must be a Solidity file (.sol)');
        process.exit(1);
      }

      if (options.format === 'terminal') {
        printBanner();
        printAnalyzing(filePath);
      }

      // Run analysis
      const report = await analyzeContract(filePath, {
        verbose: options.verbose,
        outputFormat: options.format,
        generateExploits: options.exploits !== false,
        outputDir: options.output,
      });

      // Filter by minimum severity
      const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      const minIndex = severityOrder.indexOf(options.minSeverity.toUpperCase());
      const filteredVulns = report.vulnerabilities.filter(v => {
        const vulnIndex = severityOrder.indexOf(v.severity);
        return vulnIndex <= minIndex;
      });

      if (options.format === 'json') {
        // JSON output
        console.log(formatJsonReport(report));
      } else {
        // Terminal output
        if (filteredVulns.length === 0) {
          printSuccess('No vulnerabilities detected!');
        } else {
          printInfo(`Found ${filteredVulns.length} vulnerability(ies):\n`);

          // Print vulnerabilities grouped by severity
          const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
          for (const severity of severities) {
            const vulnsOfSeverity = filteredVulns.filter(v => v.severity === severity);
            for (let i = 0; i < vulnsOfSeverity.length; i++) {
              printVulnerability(vulnsOfSeverity[i], i);
            }
          }

          // Print exploit proofs
          if (report.exploitProofs.length > 0) {
            printDivider();
            printInfo('Generated Exploit Proofs:\n');
            for (const proof of report.exploitProofs) {
              printExploitProof(proof);
            }
          }
        }

        printDivider();
        printSummary(report);
      }

      // Exit with appropriate code based on severity
      if (report.summary.critical > 0) {
        process.exit(4); // Critical vulnerabilities found
      } else if (report.summary.high > 0) {
        process.exit(3); // High severity found
      } else if (report.summary.medium > 0) {
        process.exit(2); // Medium severity found
      } else if (report.summary.low > 0) {
        process.exit(1); // Low severity found
      }
      // Exit 0 = no vulnerabilities

    } catch (error: any) {
      printError(error.message);
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

program
  .command('init')
  .description('Initialize Foundry project structure for running exploit tests')
  .addHelpText('after', `
${chalk.cyan('This command creates:')}
  - test/exploits/  Directory for generated exploit tests
  - src/            Directory for your contracts
  - lib/            Directory for dependencies
  - foundry.toml    Foundry configuration file

${chalk.cyan('After init, run:')}
  $ forge install foundry-rs/forge-std
  $ attack-sim analyze src/YourContract.sol
  $ forge test
`)
  .action(() => {
    printBanner();

    // Create necessary directories
    const dirs = ['test/exploits', 'src', 'lib'];

    for (const dir of dirs) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        printSuccess(`Created directory: ${dir}`);
      }
    }

    // Create foundry.toml if it doesn't exist
    if (!fs.existsSync('foundry.toml')) {
      const foundryConfig = `[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"

# See more config options at https://book.getfoundry.sh/reference/config/
`;
      fs.writeFileSync('foundry.toml', foundryConfig);
      printSuccess('Created foundry.toml');
    }

    printInfo('\nNext steps:');
    printInfo('1. Run: forge install foundry-rs/forge-std');
    printInfo('2. Place your contract in src/');
    printInfo('3. Run: attack-sim analyze src/YourContract.sol');
    printInfo('4. Run: forge test --match-test Exploit');
  });

// Parse arguments
program.parse();

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
