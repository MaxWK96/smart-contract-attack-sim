'use client';

import { useState } from 'react';
import { Vulnerability, Severity } from '@/lib/types';

interface ResultsViewProps {
  vulnerabilities: Vulnerability[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

const severityColors: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-red-900/50', text: 'text-red-400', border: 'border-red-700' },
  HIGH: { bg: 'bg-orange-900/50', text: 'text-orange-400', border: 'border-orange-700' },
  MEDIUM: { bg: 'bg-yellow-900/50', text: 'text-yellow-400', border: 'border-yellow-700' },
  LOW: { bg: 'bg-blue-900/50', text: 'text-blue-400', border: 'border-blue-700' },
  INFO: { bg: 'bg-gray-800', text: 'text-gray-400', border: 'border-gray-600' },
};

const severityIcons: Record<Severity, string> = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
  INFO: 'ℹ️',
};

export default function ResultsView({ vulnerabilities, summary }: ResultsViewProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (vulnerabilities.length === 0) {
    return (
      <div className="bg-green-900/30 border border-green-700 rounded-lg p-6 text-center">
        <div className="text-4xl mb-2">✅</div>
        <h3 className="text-xl font-semibold text-green-400">No Vulnerabilities Detected</h3>
        <p className="text-gray-400 mt-2">
          Your contract appears to be secure based on our static analysis.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-5 gap-2 mb-6">
        <div className="bg-red-900/30 border border-red-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-red-400">{summary.critical}</div>
          <div className="text-xs text-gray-400">Critical</div>
        </div>
        <div className="bg-orange-900/30 border border-orange-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-orange-400">{summary.high}</div>
          <div className="text-xs text-gray-400">High</div>
        </div>
        <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-yellow-400">{summary.medium}</div>
          <div className="text-xs text-gray-400">Medium</div>
        </div>
        <div className="bg-blue-900/30 border border-blue-700 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-blue-400">{summary.low}</div>
          <div className="text-xs text-gray-400">Low</div>
        </div>
        <div className="bg-gray-800 border border-gray-600 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-gray-300">{summary.total}</div>
          <div className="text-xs text-gray-400">Total</div>
        </div>
      </div>

      {/* Vulnerability List */}
      <div className="space-y-3">
        {vulnerabilities.map((vuln) => {
          const colors = severityColors[vuln.severity];
          const isExpanded = expandedId === vuln.id;

          return (
            <div
              key={vuln.id}
              className={`${colors.bg} border ${colors.border} rounded-lg overflow-hidden transition-all`}
            >
              {/* Header */}
              <button
                onClick={() => setExpandedId(isExpanded ? null : vuln.id)}
                className="w-full p-4 text-left flex items-start gap-3 hover:bg-white/5 transition-colors"
              >
                <span className="text-xl">{severityIcons[vuln.severity]}</span>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-xs px-2 py-0.5 rounded ${colors.bg} ${colors.text} font-medium border ${colors.border}`}>
                      {vuln.severity}
                    </span>
                    <span className="text-xs text-gray-500">{vuln.type}</span>
                  </div>
                  <h4 className="font-medium text-gray-100">{vuln.title}</h4>
                  <p className="text-sm text-gray-400 mt-1">
                    Line {vuln.location.line}
                    {vuln.location.functionName && ` in ${vuln.location.functionName}()`}
                    {vuln.location.contractName && ` • ${vuln.location.contractName}`}
                  </p>
                </div>
                <span className={`text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
                  ▼
                </span>
              </button>

              {/* Expanded Details */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-0 border-t border-gray-700/50">
                  <div className="space-y-3 mt-3">
                    <div>
                      <h5 className="text-xs font-medium text-gray-500 uppercase mb-1">Description</h5>
                      <p className="text-sm text-gray-300">{vuln.description}</p>
                    </div>
                    <div>
                      <h5 className="text-xs font-medium text-gray-500 uppercase mb-1">Attack Vector</h5>
                      <p className="text-sm text-gray-300">{vuln.attackVector}</p>
                    </div>
                    <div>
                      <h5 className="text-xs font-medium text-gray-500 uppercase mb-1">Recommendation</h5>
                      <p className="text-sm text-gray-300">{vuln.recommendation}</p>
                    </div>
                    {vuln.exploitable && (
                      <div className="flex items-center gap-2 text-sm">
                        <span className="text-green-400">✓</span>
                        <span className="text-gray-400">Exploit proof can be generated</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
