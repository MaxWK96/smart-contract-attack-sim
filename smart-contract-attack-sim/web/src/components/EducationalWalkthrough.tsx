'use client';

import { EducationalContent } from '@/lib/types';

interface EducationalWalkthroughProps {
  content: EducationalContent;
}

export default function EducationalWalkthrough({ content }: EducationalWalkthroughProps) {
  if (!content) {
    return null;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-lg">📚</span>
        <h4 className="text-sm font-medium text-gray-300">Educational Walkthrough</h4>
      </div>

      {/* Real World Example */}
      <div className="bg-purple-900/20 border border-purple-700/50 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-purple-400">📜</span>
          <h5 className="text-sm font-medium text-purple-300">Real-World Example</h5>
        </div>
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <span className="text-2xl font-bold text-purple-400">{content.realWorldExample.name}</span>
          </div>
          <div className="flex flex-wrap gap-4 text-sm">
            <div>
              <span className="text-gray-500">Date:</span>{' '}
              <span className="text-gray-300">{content.realWorldExample.date}</span>
            </div>
            <div>
              <span className="text-gray-500">Impact:</span>{' '}
              <span className="text-red-400 font-medium">{content.realWorldExample.impact}</span>
            </div>
          </div>
          <p className="text-sm text-gray-400 mt-2">{content.realWorldExample.description}</p>
        </div>
      </div>

      {/* Attack Flow Diagram */}
      <div className="bg-gray-800/30 border border-gray-700 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-4">
          <span className="text-blue-400">🎯</span>
          <h5 className="text-sm font-medium text-gray-300">Attack Flow</h5>
        </div>

        {/* Flow Steps */}
        <div className="space-y-0">
          {content.attackFlow.map((step, index) => (
            <div key={step.step} className="relative">
              {/* Connector Line */}
              {index < content.attackFlow.length - 1 && (
                <div className="absolute left-4 top-10 w-0.5 h-full bg-gray-700"></div>
              )}

              <div className="flex gap-4">
                {/* Step Number */}
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0 ${
                  index === 0
                    ? 'bg-blue-900/50 text-blue-400 border border-blue-700'
                    : index === content.attackFlow.length - 1
                    ? 'bg-red-900/50 text-red-400 border border-red-700'
                    : 'bg-yellow-900/50 text-yellow-400 border border-yellow-700'
                }`}>
                  {step.step}
                </div>

                {/* Step Content */}
                <div className="flex-1 pb-6">
                  <h6 className="text-sm font-medium text-gray-200 mb-1">{step.title}</h6>
                  <p className="text-sm text-gray-400">{step.description}</p>

                  {/* Code Snippet if present */}
                  {step.codeSnippet && (
                    <pre className="mt-2 text-xs text-gray-300 bg-gray-900/50 rounded p-2 overflow-x-auto border border-gray-700">
                      <code>{step.codeSnippet}</code>
                    </pre>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Key Lesson */}
      <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <span className="text-2xl">💡</span>
          <div>
            <h5 className="text-sm font-medium text-green-400 mb-1">Key Lesson</h5>
            <p className="text-sm text-gray-300">{content.keyLesson}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
