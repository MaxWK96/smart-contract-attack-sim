// SPDX-License-Identifier: MIT
// SOURCE: Based on Gnosis Safe (0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552)
// TYPE: Safe
// EXPECTED: 0 findings
// DATE_ADDED: 2026-01-17
// NOTES: Simplified Gnosis Safe multisig - requires threshold signatures

pragma solidity ^0.8.0;

contract GnosisSafe {
    event ExecutionSuccess(bytes32 txHash);
    event ExecutionFailure(bytes32 txHash);

    address[] public owners;
    uint256 public threshold;
    uint256 public nonce;

    mapping(address => bool) public isOwner;

    // SAFE: Only called once during setup
    function setup(
        address[] calldata _owners,
        uint256 _threshold
    ) external {
        require(threshold == 0, "Already initialized");
        require(_threshold > 0 && _threshold <= _owners.length, "Invalid threshold");

        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0) && !isOwner[owner], "Invalid owner");
            owners.push(owner);
            isOwner[owner] = true;
        }
        threshold = _threshold;
    }

    // SAFE: Requires valid signatures from threshold owners
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        bytes calldata signatures
    ) external returns (bool success) {
        // Access control: must be initiated by an owner
        require(isOwner[msg.sender], "Not an owner");

        bytes32 txHash = getTransactionHash(to, value, data, nonce);

        // Verify signatures from threshold owners
        checkSignatures(txHash, signatures);

        // Increment nonce to prevent replay
        nonce++;

        // Execute transaction
        (success, ) = to.call{value: value}(data);

        if (success) {
            emit ExecutionSuccess(txHash);
        } else {
            emit ExecutionFailure(txHash);
        }
    }

    function checkSignatures(bytes32 dataHash, bytes memory signatures) internal view {
        require(signatures.length >= threshold * 65, "Not enough signatures");

        address lastOwner = address(0);
        for (uint256 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signatures, i);
            address currentOwner = ecrecover(dataHash, v, r, s);

            require(isOwner[currentOwner], "Invalid signer");
            require(currentOwner > lastOwner, "Signatures not sorted");
            lastOwner = currentOwner;
        }
    }

    function signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            address(this),
            to,
            value,
            keccak256(data),
            _nonce
        ));
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    receive() external payable {}
}
