import * as path from 'path';
import {
  parseFile,
  extractContractInfo,
  findExternalCalls,
  findStateChanges,
} from '../src/utils/parser';

const FIXTURES_DIR = path.join(__dirname, 'fixtures');

describe('Solidity Parser', () => {
  describe('parseFile', () => {
    it('should parse a valid Solidity file', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast, source } = parseFile(filePath);

      expect(ast).toBeDefined();
      expect(ast.type).toBe('SourceUnit');
      expect(source).toContain('contract CleanContract');
    });

    it('should throw error for non-existent file', () => {
      expect(() => parseFile('/nonexistent/file.sol')).toThrow('File not found');
    });
  });

  describe('extractContractInfo', () => {
    it('should extract contract name and kind', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      expect(parsed.contracts.length).toBeGreaterThan(0);
      expect(parsed.contracts[0].name).toBe('CleanContract');
      expect(parsed.contracts[0].kind).toBe('contract');
    });

    it('should extract pragma version', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      expect(parsed.pragmaVersion).toContain('0.8');
    });

    it('should extract function information', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      const contract = parsed.contracts[0];
      const funcNames = contract.functions.map((f) => f.name);

      expect(funcNames).toContain('deposit');
      expect(funcNames).toContain('withdraw');
      expect(funcNames).toContain('adminWithdraw');
    });

    it('should extract function modifiers', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      const contract = parsed.contracts[0];
      const adminWithdraw = contract.functions.find((f) => f.name === 'adminWithdraw');

      expect(adminWithdraw).toBeDefined();
      expect(adminWithdraw?.modifiers).toContain('onlyOwner');
    });

    it('should extract state variables', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      const contract = parsed.contracts[0];
      const varNames = contract.stateVariables.map((v) => v.name);

      expect(varNames).toContain('owner');
      expect(varNames).toContain('balances');
    });
  });

  describe('findExternalCalls', () => {
    it('should find call() statements', () => {
      const filePath = path.join(FIXTURES_DIR, 'vulnerable-reentrancy.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      const withdrawFunc = parsed.contracts[0].functions.find((f) => f.name === 'withdraw');
      expect(withdrawFunc).toBeDefined();

      const calls = findExternalCalls(withdrawFunc!.body);

      expect(calls.length).toBeGreaterThan(0);
      expect(calls[0].type).toBe('call');
    });

    it('should return empty array for view functions', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      const getBalanceFunc = parsed.contracts[0].functions.find(
        (f) => f.name === 'getBalance'
      );
      expect(getBalanceFunc).toBeDefined();

      const calls = findExternalCalls(getBalanceFunc!.body);

      expect(calls.length).toBe(0);
    });
  });

  describe('findStateChanges', () => {
    it('should find state variable assignments', () => {
      const filePath = path.join(FIXTURES_DIR, 'vulnerable-reentrancy.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      const withdrawFunc = parsed.contracts[0].functions.find((f) => f.name === 'withdraw');
      expect(withdrawFunc).toBeDefined();

      const changes = findStateChanges(withdrawFunc!.body);

      expect(changes.length).toBeGreaterThan(0);
      expect(changes.some((c) => c.variableName === 'balances')).toBe(true);
    });

    it('should detect mapping assignments', () => {
      const filePath = path.join(FIXTURES_DIR, 'clean-contract.sol');
      const { ast } = parseFile(filePath);
      const parsed = extractContractInfo(ast);

      const depositFunc = parsed.contracts[0].functions.find((f) => f.name === 'deposit');
      expect(depositFunc).toBeDefined();

      const changes = findStateChanges(depositFunc!.body);

      expect(changes.length).toBeGreaterThan(0);
      expect(changes[0].variableName).toBe('balances');
    });
  });
});
