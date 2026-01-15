'use client';

import { useState } from 'react';
import { AnalysisLimitations } from '@/lib/types';

interface LimitationsSectionProps {
  limitations: AnalysisLimitations;
}

export default function LimitationsSection({ limitations }: LimitationsSectionProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="bg-yellow-900/20 border border-yellow-800/50 rounded-lg overflow-hidden">
      {/* Header - Always Visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 text-left flex items-start gap-3 hover:bg-yellow-900/10 transition-colors"
      >
        <span className="text-xl">⚠️</span>
        <div className="flex-1">
          <h3 className="text-sm font-medium text-yellow-400">Important Limitations</h3>
          <p className="text-xs text-gray-400 mt-1">
            This tool performs static pattern analysis only. Click to see what is and isn&apos;t covered.
          </p>
        </div>
        <span className={`text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
          ▼
        </span>
      </button>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="px-4 pb-4 border-t border-yellow-800/30">
          <div className="grid md:grid-cols-2 gap-4 mt-4">
            {/* What IS Covered */}
            <div className="bg-green-900/20 border border-green-800/50 rounded-lg p-3">
              <h4 className="text-xs font-medium text-green-400 uppercase mb-2 flex items-center gap-1">
                <span>✅</span> What This Tool Checks
              </h4>
              <ul className="text-sm text-gray-400 space-y-1">
                {limitations.covered.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-green-500 mt-0.5">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* What is NOT Covered */}
            <div className="bg-red-900/20 border border-red-800/50 rounded-lg p-3">
              <h4 className="text-xs font-medium text-red-400 uppercase mb-2 flex items-center gap-1">
                <span>❌</span> What This Tool Does NOT Check
              </h4>
              <ul className="text-sm text-gray-400 space-y-1">
                {limitations.notCovered.map((item, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-red-500 mt-0.5">•</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Disclaimer */}
          <div className="mt-4 p-3 bg-gray-800/50 rounded-lg">
            <p className="text-sm text-yellow-500/90">
              <strong>⚠️ Disclaimer:</strong> {limitations.disclaimer}
            </p>
          </div>

          {/* Call to Action */}
          <div className="mt-4 text-center">
            <p className="text-xs text-gray-500">
              For comprehensive security, consider a professional audit from firms like{' '}
              <span className="text-gray-400">Trail of Bits</span>,{' '}
              <span className="text-gray-400">OpenZeppelin</span>, or{' '}
              <span className="text-gray-400">Consensys Diligence</span>.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
