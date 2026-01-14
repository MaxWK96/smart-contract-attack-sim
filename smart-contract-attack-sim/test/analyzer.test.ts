import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { analyzeContract } from '../src/analyzer';

const FIXTURES_DIR = path.join(__dirname, 'fixtures');

describe('Analyzer Integration', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzer-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  describe('Full Analysis Pipeline', () => {
    it('should analyze vulnerable contract and generate report', async () => {
      const filePath = path.join(FIXTURES_DIR, 'vulnerable-reentrancy.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: true,
        outputDir: tempDir,
      });

      expect(report.filePath).toContain('vulnerable-reentrancy.sol');
      expect(report.contractName).toBe('VulnerableReentrancy');
      expect(report.vulnerabilities.length).toBeGreaterThan(0);
      expect(report.summary.total).toBeGreaterThan(0);
      expect(report.timestamp).toBeDefined();
    });

    it('should generate correct summary counts', async () => {
      const filePath = path.join(FIXTURES_DIR, 'multiple-vulns.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: false,
        outputDir: tempDir,
      });

      const { summary } = report;
      const totalFromCategories = summary.critical + summary.high + summary.medium + summary.low;

      expect(summary.total).toBe(totalFromCategories);
      expect(summary.critical).toBeGreaterThanOrEqual(1); // At least reentrancy
      expect(summary.high).toBeGreaterThanOrEqual(2); // At least pause/unpause
    });

    it('should include Solidity version in report', async () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: false,
        outputDir: tempDir,
      });

      expect(report.solcVersion).toContain('0.8');
    });

    it('should generate exploit proofs when enabled', async () => {
      const filePath = path.join(FIXTURES_DIR, 'vulnerable-reentrancy.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: true,
        outputDir: tempDir,
      });

      expect(report.exploitProofs.length).toBeGreaterThan(0);

      // Verify file was created
      const exploitPath = report.exploitProofs[0].testFilePath;
      expect(fs.existsSync(exploitPath)).toBe(true);
    });

    it('should NOT generate exploit proofs when disabled', async () => {
      const filePath = path.join(FIXTURES_DIR, 'vulnerable-reentrancy.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: false,
        outputDir: tempDir,
      });

      expect(report.exploitProofs.length).toBe(0);
    });
  });

  describe('Clean Contract Analysis', () => {
    it('should return zero vulnerabilities for clean contract', async () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: true,
        outputDir: tempDir,
      });

      expect(report.vulnerabilities.length).toBe(0);
      expect(report.exploitProofs.length).toBe(0);
      expect(report.summary.total).toBe(0);
    });
  });

  describe('Report JSON Structure', () => {
    it('should produce valid JSON-serializable report', async () => {
      const filePath = path.join(FIXTURES_DIR, 'vulnerable-reentrancy.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: false,
        outputDir: tempDir,
      });

      // Should not throw
      const json = JSON.stringify(report);
      const parsed = JSON.parse(json);

      expect(parsed).toHaveProperty('filePath');
      expect(parsed).toHaveProperty('contractName');
      expect(parsed).toHaveProperty('vulnerabilities');
      expect(parsed).toHaveProperty('summary');
      expect(parsed).toHaveProperty('timestamp');
    });

    it('should include all vulnerability fields in JSON', async () => {
      const filePath = path.join(FIXTURES_DIR, 'vulnerable-reentrancy.sol');

      const report = await analyzeContract(filePath, {
        generateExploits: false,
        outputDir: tempDir,
      });

      const json = JSON.stringify(report);
      const parsed = JSON.parse(json);

      expect(parsed.vulnerabilities.length).toBeGreaterThan(0);

      const vuln = parsed.vulnerabilities[0];
      expect(vuln).toHaveProperty('id');
      expect(vuln).toHaveProperty('type');
      expect(vuln).toHaveProperty('severity');
      expect(vuln).toHaveProperty('title');
      expect(vuln).toHaveProperty('description');
      expect(vuln).toHaveProperty('location');
      expect(vuln).toHaveProperty('attackVector');
      expect(vuln).toHaveProperty('recommendation');
    });
  });
});
