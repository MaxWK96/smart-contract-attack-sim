'use client';

import { useState } from 'react';
import { FixSuggestion } from '@/lib/types';

interface FixSuggestionsProps {
  suggestions: FixSuggestion[];
}

export default function FixSuggestions({ suggestions }: FixSuggestionsProps) {
  const [selectedFix, setSelectedFix] = useState<number>(
    suggestions.findIndex(s => s.recommended) ?? 0
  );

  if (!suggestions || suggestions.length === 0) {
    return null;
  }

  const currentFix = suggestions[selectedFix];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-lg">🔧</span>
        <h4 className="text-sm font-medium text-gray-300">Fix Suggestions</h4>
      </div>

      {/* Fix Option Tabs */}
      <div className="flex flex-wrap gap-2">
        {suggestions.map((fix, index) => (
          <button
            key={index}
            onClick={() => setSelectedFix(index)}
            className={`px-3 py-1.5 text-sm rounded-lg border transition-all flex items-center gap-2 ${
              selectedFix === index
                ? 'bg-blue-900/50 border-blue-600 text-blue-300'
                : 'bg-gray-800/50 border-gray-700 text-gray-400 hover:border-gray-600'
            }`}
          >
            {fix.name}
            {fix.recommended && (
              <span className="text-xs bg-green-900/50 text-green-400 px-1.5 py-0.5 rounded border border-green-700">
                Recommended
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Selected Fix Details */}
      <div className="bg-gray-800/30 rounded-lg border border-gray-700 overflow-hidden">
        {/* Gas Impact Header */}
        <div className="px-4 py-2 bg-gray-900/50 border-b border-gray-700 flex items-center justify-between">
          <span className="text-sm text-gray-300">{currentFix.description}</span>
          <span className={`text-xs px-2 py-1 rounded ${
            currentFix.gasImpact === 'None'
              ? 'bg-green-900/50 text-green-400 border border-green-700'
              : 'bg-yellow-900/50 text-yellow-400 border border-yellow-700'
          }`}>
            Gas: {currentFix.gasImpact}
          </span>
        </div>

        {/* Code Comparison */}
        <div className="grid md:grid-cols-2 divide-x divide-gray-700">
          {/* Vulnerable Code */}
          <div className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-red-400">✗</span>
              <span className="text-xs font-medium text-red-400 uppercase">Vulnerable</span>
            </div>
            <pre className="text-xs text-gray-300 bg-red-900/10 rounded p-3 overflow-x-auto border border-red-900/30">
              <code>{currentFix.vulnerableCode}</code>
            </pre>
          </div>

          {/* Fixed Code */}
          <div className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-green-400">✓</span>
              <span className="text-xs font-medium text-green-400 uppercase">Fixed</span>
            </div>
            <pre className="text-xs text-gray-300 bg-green-900/10 rounded p-3 overflow-x-auto border border-green-900/30">
              <code>{currentFix.fixedCode}</code>
            </pre>
          </div>
        </div>

        {/* Pros and Cons */}
        <div className="grid md:grid-cols-2 divide-x divide-gray-700 border-t border-gray-700">
          {/* Pros */}
          <div className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-green-400">+</span>
              <span className="text-xs font-medium text-gray-400 uppercase">Pros</span>
            </div>
            <ul className="space-y-1">
              {currentFix.pros.map((pro, i) => (
                <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                  <span className="text-green-500 mt-0.5">+</span>
                  <span>{pro}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Cons */}
          <div className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-red-400">-</span>
              <span className="text-xs font-medium text-gray-400 uppercase">Cons</span>
            </div>
            <ul className="space-y-1">
              {currentFix.cons.map((con, i) => (
                <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                  <span className="text-red-500 mt-0.5">-</span>
                  <span>{con}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
