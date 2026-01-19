'use client';

import { useState } from 'react';
import CodeEditor from '@/components/CodeEditor';
import ResultsView from '@/components/ResultsView';
import ExploitViewer from '@/components/ExploitViewer';
import LimitationsSection from '@/components/LimitationsSection';
import { AnalysisResult } from '@/lib/types';

export default function Home() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!code.trim()) {
      setError('Please enter some Solidity code to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Analysis failed');
      }

      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="text-2xl">🔒</div>
              <div>
                <h1 className="text-xl font-bold text-gray-100">
                  Smart Contract Attack Simulator
                </h1>
                <p className="text-sm text-gray-500">
                  Static Analysis & Exploit Generation for Solidity
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <a
                href="https://github.com/MaxWK96/smart-contract-attack-sim"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg transition-colors border border-gray-700"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                <span>View Source</span>
                <span className="text-xs text-gray-500">Open Source</span>
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Disclaimer */}
      <div className="bg-yellow-900/20 border-b border-yellow-800/50">
        <div className="max-w-7xl mx-auto px-4 py-2">
          <p className="text-sm text-yellow-500/90 text-center">
            <strong>Educational & Defensive Use Only</strong> — Only analyze contracts you own or have permission to test.
          </p>
        </div>
      </div>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* How It Works Section */}
        <div className="mb-8 grid md:grid-cols-2 gap-6">
          {/* What This Tool Does */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-gray-200 mb-4">How It Works</h2>
            <p className="text-sm text-gray-400 mb-4">
              Static analysis on Solidity contracts to detect common vulnerability patterns:
            </p>
            <ul className="space-y-2 text-sm">
              <li className="flex items-start gap-2">
                <span className="text-red-400 mt-0.5">●</span>
                <span className="text-gray-300"><strong>Reentrancy</strong> — External calls before state updates</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-orange-400 mt-0.5">●</span>
                <span className="text-gray-300"><strong>Access Control</strong> — Missing permission checks on sensitive functions</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-yellow-400 mt-0.5">●</span>
                <span className="text-gray-300"><strong>Unchecked Calls</strong> — Ignored return values from external calls</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-purple-400 mt-0.5">●</span>
                <span className="text-gray-300"><strong>Selfdestruct</strong> — Unprotected contract destruction</span>
              </li>
            </ul>
            <div className="mt-4 pt-4 border-t border-gray-800">
              <p className="text-sm text-gray-500">
                For each finding: executable Foundry test, multiple fix options, real-world examples.
              </p>
            </div>
          </div>

          {/* Limitations */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-gray-200 mb-4">Limitations</h2>
            <p className="text-sm text-gray-400 mb-4">
              This tool does <strong className="text-gray-300">NOT</strong> detect:
            </p>
            <ul className="space-y-1.5 text-sm text-gray-500">
              <li className="flex items-center gap-2">
                <span className="text-gray-600">✗</span>
                <span>Economic attacks (flash loans, price manipulation)</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-gray-600">✗</span>
                <span>Governance attacks (malicious proposals)</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-gray-600">✗</span>
                <span>Oracle manipulation</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-gray-600">✗</span>
                <span>Time-based attacks (timestamp dependence)</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-gray-600">✗</span>
                <span>Business logic bugs specific to your application</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="text-gray-600">✗</span>
                <span>Social engineering or off-chain exploits</span>
              </li>
            </ul>
            <div className="mt-4 pt-4 border-t border-gray-800">
              <p className="text-sm text-gray-400">
                <strong className="text-gray-300">For production:</strong> Professional audit required. This is one layer of defense.
              </p>
            </div>
          </div>
        </div>

        {/* Validation Results */}
        <div className="mb-8 bg-gray-900/30 border border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-200 mb-4">Validation Results</h2>
          <div className="grid md:grid-cols-2 gap-6">
            {/* Safe Contracts */}
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-3">Tested Against Production Contracts</h3>
              <ul className="space-y-1.5 text-sm">
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">WETH9</span>
                  <span className="text-gray-600">— 0 vulnerabilities (correct)</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">Uniswap V2 Pair</span>
                  <span className="text-gray-600">— 0 vulnerabilities (correct)</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">Gnosis Safe</span>
                  <span className="text-gray-600">— 0 vulnerabilities (correct)</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">Compound cToken</span>
                  <span className="text-gray-600">— 0 vulnerabilities (correct)</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">OpenZeppelin ERC20</span>
                  <span className="text-gray-600">— 0 vulnerabilities (correct)</span>
                </li>
              </ul>
              <p className="mt-3 text-sm text-gray-500">
                <strong className="text-gray-400">False Positive Rate:</strong> 0/5 (0%)
              </p>
            </div>

            {/* Vulnerable Contracts */}
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-3">Verified Against Historical Exploits</h3>
              <ul className="space-y-1.5 text-sm">
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">The DAO (2016, $60M)</span>
                  <span className="text-gray-600">— Reentrancy detected</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">Parity Wallet (2017, $280M)</span>
                  <span className="text-gray-600">— Selfdestruct detected</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">King of Ether (2016)</span>
                  <span className="text-gray-600">— Unchecked call detected</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">Rubixi</span>
                  <span className="text-gray-600">— Access control detected</span>
                </li>
                <li className="flex items-center gap-2">
                  <span className="text-green-500">✓</span>
                  <span className="text-gray-300">SpankChain (2018, $40k)</span>
                  <span className="text-gray-600">— Reentrancy detected</span>
                </li>
              </ul>
              <p className="mt-3 text-sm text-gray-500">
                <strong className="text-gray-400">Detection Rate:</strong> 5/5 (100%)
              </p>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-gray-800 flex items-center justify-between">
            <p className="text-xs text-gray-600">
              All tests deterministic and reproducible.
            </p>
            <a
              href="https://github.com/MaxWK96/smart-contract-attack-sim/tree/master/test"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              View full test suite →
            </a>
          </div>
        </div>

        {/* Analyzer Section */}
        <div className="grid lg:grid-cols-2 gap-8">
          {/* Left Column - Input */}
          <div className="space-y-4">
            <CodeEditor value={code} onChange={setCode} />

            <button
              onClick={handleAnalyze}
              disabled={loading || !code.trim()}
              className={`w-full py-3 px-4 rounded-lg font-medium transition-all flex items-center justify-center gap-2 ${
                loading || !code.trim()
                  ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-500 text-white'
              }`}
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <span>Analyzing...</span>
                </>
              ) : (
                <span>Analyze Contract</span>
              )}
            </button>

            {/* Error Display */}
            {error && (
              <div className="bg-red-900/30 border border-red-700 rounded-lg p-4">
                <p className="text-red-400 text-sm">
                  <strong>Error:</strong> {error}
                </p>
              </div>
            )}
          </div>

          {/* Right Column - Results */}
          <div className="space-y-6">
            {result ? (
              <>
                {/* Contract Info */}
                <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
                  <div className="flex items-center gap-4 text-sm">
                    <div>
                      <span className="text-gray-500">Contract:</span>{' '}
                      <span className="text-gray-200 font-medium">{result.contractName}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Solidity:</span>{' '}
                      <span className="text-gray-200">{result.solcVersion || 'Unknown'}</span>
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities */}
                <ResultsView
                  vulnerabilities={result.vulnerabilities}
                  summary={result.summary}
                  safetyChecks={result.safetyChecks}
                />

                {/* Exploit Code */}
                {result.exploitCode && (
                  <ExploitViewer
                    code={result.exploitCode}
                    contractName={result.contractName}
                  />
                )}

                {/* Limitations Section */}
                <LimitationsSection limitations={result.limitations} />
              </>
            ) : (
              <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-8 text-center">
                <div className="text-4xl mb-4">🔐</div>
                <h3 className="text-lg font-medium text-gray-300 mb-2">
                  Ready to Analyze
                </h3>
                <p className="text-gray-500 text-sm">
                  Paste your Solidity contract code on the left and click
                  &quot;Analyze Contract&quot; to begin analysis.
                </p>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-gray-500">
            <div className="flex items-center gap-4">
              <p>Static analysis tool — not a substitute for professional audit.</p>
              <span className="hidden sm:inline text-gray-700">|</span>
              <p className="text-gray-600">
                <strong className="text-gray-500">Privacy:</strong> Contract code is analyzed server-side but not stored.
              </p>
            </div>
            <p className="text-gray-600">
              Built with Next.js • Not connected to any blockchain
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
