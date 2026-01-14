'use client';

import { useState } from 'react';
import CodeEditor from '@/components/CodeEditor';
import ResultsView from '@/components/ResultsView';
import ExploitViewer from '@/components/ExploitViewer';
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
                  Vulnerability Detection & Exploit Generation
                </p>
              </div>
            </div>
            <a
              href="https://github.com/MaxWK96/smart-contract-attack-sim"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
              <span>GitHub</span>
            </a>
          </div>
        </div>
      </header>

      {/* Disclaimer */}
      <div className="bg-yellow-900/20 border-b border-yellow-800/50">
        <div className="max-w-7xl mx-auto px-4 py-2">
          <p className="text-sm text-yellow-500/90 text-center">
            ⚠️ <strong>Educational & Defensive Use Only</strong> — Only analyze contracts you own or have permission to test.
            This tool performs static analysis and generates test simulations.
          </p>
        </div>
      </div>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
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
                <>
                  <span>🔍</span>
                  <span>Analyze Contract</span>
                </>
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
                />

                {/* Exploit Code */}
                {result.exploitCode && (
                  <ExploitViewer
                    code={result.exploitCode}
                    contractName={result.contractName}
                  />
                )}
              </>
            ) : (
              <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-8 text-center">
                <div className="text-4xl mb-4">🔐</div>
                <h3 className="text-lg font-medium text-gray-300 mb-2">
                  Ready to Analyze
                </h3>
                <p className="text-gray-500 text-sm">
                  Paste your Solidity contract code on the left and click
                  &quot;Analyze Contract&quot; to detect vulnerabilities.
                </p>
                <div className="mt-6 grid grid-cols-2 gap-3 text-sm">
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <div className="text-red-400 font-medium">Reentrancy</div>
                    <div className="text-gray-500 text-xs">Call before state update</div>
                  </div>
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <div className="text-orange-400 font-medium">Access Control</div>
                    <div className="text-gray-500 text-xs">Missing auth checks</div>
                  </div>
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <div className="text-yellow-400 font-medium">Overflow</div>
                    <div className="text-gray-500 text-xs">Integer overflow/underflow</div>
                  </div>
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <div className="text-purple-400 font-medium">Selfdestruct</div>
                    <div className="text-gray-500 text-xs">Unprotected destroy</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-gray-500">
            <p>
              Results are simulations based on static analysis — not guarantees of security.
            </p>
            <p>
              Built with Next.js • Not connected to any live blockchain
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
