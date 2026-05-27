// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  PsoProtocol — Solidity binding for the pso-protocol precompiles.
/// @notice Thin `staticcall` wrappers around the on-chain precompiles that
///         expose the canonical PSO hash formulas. Every function in this
///         library returns the **same bytes** as the corresponding Rust
///         function in the `pso-protocol` crate.
///
///         This library is `internal`-only — inlined at consumer compile
///         time, with no separate deployment and no cross-contract call
///         gas. Consumers depend on it via Foundry's `forge install` /
///         remapping mechanism.
///
/// @dev    Precompile address allocation (reserved range 0x0210..0x021F):
///
///         | Address  | Function                                |
///         | -------- | --------------------------------------- |
///         | 0x0210   | computeBindingHash                      |
///         | 0x0211   | computeTributeDraftHash                 |
///         | 0x0212   | computeSpendingUnitHash                 |
///         | 0x0213.. | reserved for future named formulas      |
///
///         No TD-id or SU-id precompile: TD-id's Poseidon formula
///         takes an `owner` input that bakes in off-chain nonce
///         randomness, and SU ids are random by construction — in
///         both cases the ZK proof is the only legitimate witness,
///         so on-chain recomputation adds nothing.
///
///         The raw Poseidon precompile at `0x0202` is kept for third-party
///         L2 apps that need Poseidon for non-PSO bindings. The pso-protocol
///         precompiles are additive, not replacement.
library PsoProtocol {
    /// @notice Reverts when a precompile call fails or returns the wrong length.
    error PsoProtocolPrecompileFailed(address precompile);

    /// @dev Precompile addresses. Keep these in lock-step with
    ///      `crates/pso-chain/src/config.rs`.
    address internal constant BINDING_HASH_PRECOMPILE = address(0x0210);
    address internal constant TD_HASH_PRECOMPILE = address(0x0211);
    address internal constant SU_HASH_PRECOMPILE = address(0x0212);

    // ---------------------------------------------------------------------
    // Binding hash
    // ---------------------------------------------------------------------

    /// @notice Compute the off-chain ↔ on-chain binding hash for a tribute
    ///         draft. Mirrors `pso_protocol::binding::compute_binding_hash`
    ///         byte-for-byte.
    ///
    /// @dev    Input layout (96 bytes, big-endian uint256 slots):
    ///         `[sender_padded_uint256 | tributeDraftId | chainId]`.
    ///
    /// @param  sender         The EVM address binding the proof.
    /// @param  tributeDraftId The TD id being bound (as `uint256`).
    /// @param  chainId        The chain id of the verifying network.
    /// @return The 32-byte BN254 Fr digest, big-endian.
    function computeBindingHash(address sender, uint256 tributeDraftId, uint256 chainId)
        internal
        view
        returns (bytes32)
    {
        bytes memory input = abi.encodePacked(uint256(uint160(sender)), tributeDraftId, chainId);
        (bool ok, bytes memory ret) = BINDING_HASH_PRECOMPILE.staticcall(input);
        if (!ok || ret.length != 32) revert PsoProtocolPrecompileFailed(BINDING_HASH_PRECOMPILE);
        return bytes32(ret);
    }

    // ---------------------------------------------------------------------
    // TributeDraft
    // ---------------------------------------------------------------------

    /// @notice Compute the TributeDraft entity hash.
    ///
    /// @dev    Input layout (32 × (4 + N) bytes, big-endian uint256 slots):
    ///         `[id | currency_padded | base_padded | atto_padded | su_id_0 | ... | su_id_{N-1}]`.
    ///         The precompile derives `N` from `(input.length - 128) / 32`.
    function computeTributeDraftHash(
        bytes32 id,
        uint16 currency,
        uint64 amountBase,
        uint64 amountAtto,
        bytes32[] memory suIds
    ) internal view returns (bytes32) {
        bytes memory input = abi.encodePacked(
            id,
            uint256(currency),
            uint256(amountBase),
            uint256(amountAtto),
            _packBytes32Array(suIds)
        );
        (bool ok, bytes memory ret) = TD_HASH_PRECOMPILE.staticcall(input);
        if (!ok || ret.length != 32) revert PsoProtocolPrecompileFailed(TD_HASH_PRECOMPILE);
        return bytes32(ret);
    }

    // ---------------------------------------------------------------------
    // SpendingUnit
    // ---------------------------------------------------------------------

    /// @notice Compute the SpendingUnit entity hash.
    ///
    /// @dev    Input layout (variable, big-endian uint256 slots):
    ///         `[id | owner | wwd_padded | currency_padded | base_padded |`
    ///         `atto_padded | sr_count_padded | sr_0 | ... | sr_{M-1} |`
    ///         `ar_count_padded | ar_0 | ... | ar_{K-1}]`.
    ///
    ///         The two count slots are required because SR and AR are
    ///         separate vectors entering the iterated chain at different
    ///         points — without explicit lengths the precompile cannot
    ///         tell where one vector ends and the other begins.
    function computeSpendingUnitHash(
        bytes32 id,
        bytes32 owner,
        uint64 worldwideDay,
        uint16 currency,
        uint64 amountBase,
        uint64 amountAtto,
        bytes32[] memory spendingRecordFingerprints,
        bytes32[] memory amendmentRecordFingerprints
    ) internal view returns (bytes32) {
        bytes memory input = abi.encodePacked(
            id,
            owner,
            uint256(worldwideDay),
            uint256(currency),
            uint256(amountBase),
            uint256(amountAtto),
            uint256(spendingRecordFingerprints.length),
            _packBytes32Array(spendingRecordFingerprints),
            uint256(amendmentRecordFingerprints.length),
            _packBytes32Array(amendmentRecordFingerprints)
        );
        (bool ok, bytes memory ret) = SU_HASH_PRECOMPILE.staticcall(input);
        if (!ok || ret.length != 32) revert PsoProtocolPrecompileFailed(SU_HASH_PRECOMPILE);
        return bytes32(ret);
    }

    /// @dev Concatenate `bytes32[]` into `bytes` without ABI length prefix.
    ///      `abi.encodePacked(bytes32[])` already produces this in current
    ///      solc, but extracting the call keeps the encoding intent
    ///      explicit at every call site.
    function _packBytes32Array(bytes32[] memory arr) private pure returns (bytes memory out) {
        uint256 len = arr.length;
        out = new bytes(len * 32);
        assembly {
            let dst := add(out, 0x20)
            let src := add(arr, 0x20)
            let size := mul(len, 0x20)
            // memcpy: src..src+size → dst..dst+size
            for { let i := 0 } lt(i, size) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }
}
