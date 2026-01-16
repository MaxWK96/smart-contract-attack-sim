#!/usr/bin/env python3
"""
Real-World Contract Test Suite
Tests analyzer against production contracts from Etherscan/GitHub
"""

import json
import os
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

API_URL = "http://localhost:3000/api/analyze"

# Expected results for safe contracts
SAFE_CONTRACTS = {
    "weth.sol": {
        "name": "WETH9",
        "source": "Etherscan 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "expected_vulns": 0,
    },
    "oz-erc20.sol": {
        "name": "OpenZeppelin ERC20 + Ownable",
        "source": "OpenZeppelin Contracts v4.9.0",
        "expected_vulns": 0,
    },
    "uniswap-v2-pair.sol": {
        "name": "Uniswap V2 Pair",
        "source": "Uniswap V2 Core",
        "expected_vulns": 0,
    },
    "gnosis-safe.sol": {
        "name": "Gnosis Safe Multisig",
        "source": "Gnosis Safe",
        "expected_vulns": 0,
    },
    "compound-ctoken.sol": {
        "name": "Compound cToken",
        "source": "Compound Finance",
        "expected_vulns": 0,
    },
}

# Expected results for vulnerable contracts
VULNERABLE_CONTRACTS = {
    "dao-reentrancy.sol": {
        "name": "The DAO",
        "source": "The DAO Hack (June 2016)",
        "expected_types": ["reentrancy"],
        "impact": "$60M stolen",
    },
    "parity-multisig.sol": {
        "name": "Parity Multisig Library",
        "source": "Parity Wallet (November 2017)",
        "expected_types": ["unprotected-selfdestruct", "access-control"],
        "impact": "$280M frozen",
    },
    "king-of-ether.sol": {
        "name": "King of the Ether",
        "source": "King of Ether Throne (2016)",
        "expected_types": ["unchecked-call"],
        "impact": "Game funds stuck",
    },
    "rubixi-access-control.sol": {
        "name": "Rubixi",
        "source": "Rubixi pyramid scheme",
        "expected_types": ["access-control"],
        "impact": "Creator takeover",
    },
    "spankchain-reentrancy.sol": {
        "name": "SpankChain",
        "source": "SpankChain (October 2018)",
        "expected_types": ["reentrancy"],
        "impact": "$40k stolen",
    },
}


def read_contract(filepath):
    """Read contract source from file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


def analyze_contract(code):
    """Send contract to analyzer API."""
    data = json.dumps({"code": code}).encode('utf-8')
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}


def test_safe_contracts(base_path):
    """Test all safe contracts - expect 0 vulnerabilities."""
    print("\n" + "=" * 70)
    print("SAFE CONTRACTS (Expected: 0 vulnerabilities)")
    print("=" * 70)

    passed = 0
    failed = 0
    results = []

    safe_path = base_path / "safe"
    for filename, expected in SAFE_CONTRACTS.items():
        filepath = safe_path / filename
        if not filepath.exists():
            print(f"[SKIP] {expected['name']}: File not found")
            continue

        code = read_contract(filepath)
        result = analyze_contract(code)

        if "error" in result:
            print(f"[ERROR] {expected['name']}: {result['error']}")
            failed += 1
            continue

        total = result.get("summary", {}).get("total", 0)
        vulns = result.get("vulnerabilities", [])

        if total == 0:
            print(f"[PASS] {expected['name']}: 0 vulnerabilities")
            passed += 1
            results.append({
                "name": expected["name"],
                "source": expected["source"],
                "status": "PASS",
                "vulnerabilities": 0,
            })
        else:
            print(f"[FAIL] {expected['name']}: {total} FALSE POSITIVES")
            for v in vulns:
                print(f"       - {v['type']}: {v['title']} (line {v['location']['line']})")
            failed += 1
            results.append({
                "name": expected["name"],
                "source": expected["source"],
                "status": "FAIL",
                "vulnerabilities": total,
                "false_positives": [v['type'] for v in vulns],
            })

    print(f"\nSafe Contracts: {passed}/{passed + failed} passed")
    print(f"False Positive Rate: {failed}/{passed + failed} ({failed * 100 // (passed + failed) if (passed + failed) > 0 else 0}%)")

    return passed, failed, results


def test_vulnerable_contracts(base_path):
    """Test all vulnerable contracts - expect correct detections."""
    print("\n" + "=" * 70)
    print("VULNERABLE CONTRACTS (Expected: Correct detection)")
    print("=" * 70)

    passed = 0
    failed = 0
    results = []

    vuln_path = base_path / "vulnerable"
    for filename, expected in VULNERABLE_CONTRACTS.items():
        filepath = vuln_path / filename
        if not filepath.exists():
            print(f"[SKIP] {expected['name']}: File not found")
            continue

        code = read_contract(filepath)
        result = analyze_contract(code)

        if "error" in result:
            print(f"[ERROR] {expected['name']}: {result['error']}")
            failed += 1
            continue

        vulns = result.get("vulnerabilities", [])
        detected_types = set(v["type"] for v in vulns)
        expected_types = set(expected["expected_types"])

        # Check if at least one expected type was detected
        found = detected_types.intersection(expected_types)

        if found:
            print(f"[PASS] {expected['name']}: Detected {', '.join(found)}")
            passed += 1
            results.append({
                "name": expected["name"],
                "source": expected["source"],
                "impact": expected["impact"],
                "status": "PASS",
                "expected": list(expected_types),
                "detected": list(detected_types),
            })
        else:
            print(f"[FAIL] {expected['name']}: Expected {expected_types}, got {detected_types}")
            failed += 1
            results.append({
                "name": expected["name"],
                "source": expected["source"],
                "impact": expected["impact"],
                "status": "FAIL",
                "expected": list(expected_types),
                "detected": list(detected_types),
            })

    print(f"\nVulnerable Contracts: {passed}/{passed + failed} detected")
    print(f"True Positive Rate: {passed}/{passed + failed} ({passed * 100 // (passed + failed) if (passed + failed) > 0 else 0}%)")

    return passed, failed, results


def generate_report(safe_results, vuln_results, output_path):
    """Generate JSON report of results."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "safe_contracts": safe_results[2],
        "vulnerable_contracts": vuln_results[2],
        "summary": {
            "safe_passed": safe_results[0],
            "safe_failed": safe_results[1],
            "vulnerable_passed": vuln_results[0],
            "vulnerable_failed": vuln_results[1],
            "false_positive_rate": f"{safe_results[1]}/{safe_results[0] + safe_results[1]}",
            "true_positive_rate": f"{vuln_results[0]}/{vuln_results[0] + vuln_results[1]}",
        }
    }

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    return report


def main():
    print("=" * 70)
    print("REAL-WORLD CONTRACT TEST SUITE")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Determine paths
    script_dir = Path(__file__).parent
    base_path = script_dir / "real-world"
    results_path = script_dir / "test-results"

    # Run tests
    safe_results = test_safe_contracts(base_path)
    vuln_results = test_vulnerable_contracts(base_path)

    # Generate report
    results_path.mkdir(exist_ok=True)
    report = generate_report(
        safe_results,
        vuln_results,
        results_path / "real-world-results.json"
    )

    # Final summary
    total_safe = safe_results[0] + safe_results[1]
    total_vuln = vuln_results[0] + vuln_results[1]
    total_passed = safe_results[0] + vuln_results[0]
    total_tests = total_safe + total_vuln

    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    print(f"Safe Contracts:       {safe_results[0]}/{total_safe} (0 false positives required)")
    print(f"Vulnerable Contracts: {vuln_results[0]}/{total_vuln} (100% detection required)")
    print("-" * 70)
    print(f"OVERALL: {total_passed}/{total_tests} contracts analyzed correctly")
    print("=" * 70)

    if safe_results[1] == 0 and vuln_results[1] == 0:
        print("\nSUCCESS: All tests passed!")
        return True
    else:
        print("\nFAILURE: Some tests failed. Review results above.")
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
