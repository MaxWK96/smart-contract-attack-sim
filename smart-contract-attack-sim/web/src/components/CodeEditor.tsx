'use client';

import { useState } from 'react';

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

const SAMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: External call before state update
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // State update AFTER call!
    }
}`;

export default function CodeEditor({ value, onChange, placeholder }: CodeEditorProps) {
  const [lineCount, setLineCount] = useState(1);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value;
    onChange(newValue);
    setLineCount(newValue.split('\n').length);
  };

  const loadSample = () => {
    onChange(SAMPLE_CONTRACT);
    setLineCount(SAMPLE_CONTRACT.split('\n').length);
  };

  return (
    <div className="relative">
      <div className="flex justify-between items-center mb-2">
        <label className="text-sm font-medium text-gray-300">
          Solidity Code
        </label>
        <button
          onClick={loadSample}
          className="text-xs px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors"
        >
          Load Sample Contract
        </button>
      </div>
      <div className="relative flex bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
        {/* Line numbers */}
        <div className="flex-shrink-0 bg-gray-800 text-gray-500 text-right py-4 px-2 select-none font-mono text-sm border-r border-gray-700">
          {Array.from({ length: Math.max(lineCount, 20) }, (_, i) => (
            <div key={i + 1} className="leading-6">
              {i + 1}
            </div>
          ))}
        </div>
        {/* Code textarea */}
        <textarea
          value={value}
          onChange={handleChange}
          placeholder={placeholder || 'Paste your Solidity contract here...'}
          className="flex-1 bg-transparent text-gray-100 font-mono text-sm p-4 resize-none focus:outline-none min-h-[400px] leading-6"
          spellCheck={false}
        />
      </div>
      <p className="mt-2 text-xs text-gray-500">
        {value.length} characters | {lineCount} lines
      </p>
    </div>
  );
}
