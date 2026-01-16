#!/usr/bin/env python3
"""
Determinism Test Suite
Verifies that the analyzer produces IDENTICAL results on repeated runs.
"""

import json
import urllib.request
import urllib.error
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Tuple

API_URL = "http://localhost:3000/api/analyze"
NUM_RUNS = 10

# =============================================================================
# Test Contracts
# =============================================================================

CONTRACT_1_REENTRANCY = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}'''

CONTRACT_2_ACCESS_CONTROL = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function withdrawAll(address to) external {
        payable(to).transfer(address(this).balance);
    }

    receive() external payable {}
}'''

CONTRACT_3_UNCHECKED_CALL = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract KingOfEther {
    address public king;
    uint256 public prize;

    constructor() payable {
        king = msg.sender;
        prize = msg.value;
    }

    function claimThrone() external payable {
        require(msg.value > prize, "Need more ETH");

        address previousKing = king;
        uint256 previousPrize = prize;

        king = msg.sender;
        prize = msg.value;

        payable(previousKing).send(previousPrize);
    }

    function claimThroneV2() external payable {
        require(msg.value > prize, "Need more ETH");

        address previousKing = king;
        uint256 previousPrize = prize;

        king = msg.sender;
        prize = msg.value;

        previousKing.call{value: previousPrize}("");
    }
}'''

TEST_CONTRACTS = [
    ("Reentrancy", CONTRACT_1_REENTRANCY),
    ("Access Control", CONTRACT_2_ACCESS_CONTROL),
    ("Unchecked Call", CONTRACT_3_UNCHECKED_CALL),
]


def analyze_contract(code: str) -> Tuple[bool, Dict[str, Any]]:
    """Run analyzer on contract and return results."""
    data = json.dumps({"code": code}).encode('utf-8')
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            result = json.loads(response.read().decode('utf-8'))
            return True, result
    except Exception as e:
        return False, {"error": str(e)}


def normalize_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize result for comparison by removing non-deterministic fields.
    Keep only fields that SHOULD be deterministic.
    """
    if "error" in result:
        return result

    normalized = {
        "summary": result.get("summary", {}),
        "vulnerabilities": []
    }

    for vuln in result.get("vulnerabilities", []):
        normalized_vuln = {
            "type": vuln.get("type"),
            "title": vuln.get("title"),
            "severity": vuln.get("severity"),
            "confidence": vuln.get("confidence"),
            "confidenceScore": vuln.get("confidenceScore"),
            "location": vuln.get("location"),
            "description": vuln.get("description"),
            # Include fix suggestion count but not full content
            "fixSuggestionCount": len(vuln.get("fixSuggestions", [])),
            # Include educational content indicator
            "hasEducational": vuln.get("educational") is not None,
        }
        normalized["vulnerabilities"].append(normalized_vuln)

    # Sort vulnerabilities for consistent ordering
    normalized["vulnerabilities"].sort(
        key=lambda v: (v["type"], v["location"].get("line", 0))
    )

    # Include exploit code hash (content should be deterministic)
    if result.get("exploitCode"):
        normalized["exploitCodeHash"] = hashlib.md5(
            result["exploitCode"].encode()
        ).hexdigest()

    return normalized


def compute_hash(result: Dict[str, Any]) -> str:
    """Compute a hash of the normalized result for quick comparison."""
    normalized = normalize_result(result)
    json_str = json.dumps(normalized, sort_keys=True)
    return hashlib.md5(json_str.encode()).hexdigest()


def compare_results(results: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """
    Compare all results for exact match.
    Returns (all_match, list of differences).
    """
    if len(results) < 2:
        return True, []

    differences = []
    base = normalize_result(results[0])
    base_hash = compute_hash(results[0])

    for i, result in enumerate(results[1:], start=2):
        current_hash = compute_hash(result)

        if current_hash != base_hash:
            # Find specific differences
            current = normalize_result(result)

            # Compare summaries
            if base["summary"] != current["summary"]:
                differences.append(f"Run {i}: Summary differs")
                differences.append(f"  Base: {base['summary']}")
                differences.append(f"  Run {i}: {current['summary']}")

            # Compare vulnerability count
            if len(base["vulnerabilities"]) != len(current["vulnerabilities"]):
                differences.append(
                    f"Run {i}: Vulnerability count differs "
                    f"({len(base['vulnerabilities'])} vs {len(current['vulnerabilities'])})"
                )

            # Compare individual vulnerabilities
            for j, (v1, v2) in enumerate(zip(base["vulnerabilities"], current["vulnerabilities"])):
                for key in ["type", "title", "severity", "confidence", "confidenceScore", "location"]:
                    if v1.get(key) != v2.get(key):
                        differences.append(
                            f"Run {i}, Vuln {j+1}: {key} differs "
                            f"({v1.get(key)} vs {v2.get(key)})"
                        )

            # Compare exploit code hash
            if base.get("exploitCodeHash") != current.get("exploitCodeHash"):
                differences.append(f"Run {i}: Exploit code content differs")

    return len(differences) == 0, differences


def test_contract_determinism(name: str, code: str) -> Tuple[bool, int, List[str]]:
    """
    Test determinism for a single contract.
    Returns (success, identical_count, differences).
    """
    print(f"\n  Running {NUM_RUNS} analyses...", end=" ", flush=True)

    results = []
    errors = []

    for i in range(NUM_RUNS):
        success, result = analyze_contract(code)
        if success:
            results.append(result)
        else:
            errors.append(f"Run {i+1}: {result.get('error', 'Unknown error')}")

    if errors:
        print("ERRORS")
        return False, 0, errors

    print("Done")

    # Compare all results
    all_match, differences = compare_results(results)

    if all_match:
        return True, NUM_RUNS, []
    else:
        return False, 0, differences


def main():
    print("=" * 70)
    print("DETERMINISM TEST SUITE")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Runs per contract: {NUM_RUNS}")
    print("=" * 70)

    all_passed = True
    report_lines = []

    for name, code in TEST_CONTRACTS:
        print(f"\nTesting: {name}")
        success, identical_count, differences = test_contract_determinism(name, code)

        if success:
            status = f"{NUM_RUNS}/{NUM_RUNS} runs identical"
            icon = "PASS"
            report_lines.append(f"Contract ({name}): {status} [PASS]")
        else:
            status = f"FAILED - variations detected"
            icon = "FAIL"
            all_passed = False
            report_lines.append(f"Contract ({name}): {status} [FAIL]")

            # Print differences
            print(f"\n  Differences found:")
            for diff in differences[:10]:  # Limit output
                print(f"    {diff}")
            if len(differences) > 10:
                print(f"    ... and {len(differences) - 10} more")

        print(f"  Result: [{icon}] {status}")

    # Final report
    print("\n" + "=" * 70)
    print("DETERMINISM TEST RESULTS")
    print("=" * 70)

    for line in report_lines:
        print(line)

    print("-" * 70)

    if all_passed:
        print("RESULT: All tests passed - analyzer is deterministic")
        print("=" * 70)
        return True
    else:
        print("RESULT: FAILED - Non-deterministic behavior detected")
        print("=" * 70)
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
