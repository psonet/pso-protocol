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
///         | 0x0211   | computeTributeDraftId                   |
///         | 0x0212   | computeTributeDraftHash                 |
///         | 0x0213   | computeSpendingUnitId                   |
///         | 0x0214   | computeSpendingUnitHash                 |
///         | 0x0215.. | reserved for future named formulas      |
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
    address internal constant TD_ID_PRECOMPILE = address(0x0211);
    address internal constant TD_HASH_PRECOMPILE = address(0x0212);
    address internal constant SU_ID_PRECOMPILE = address(0x0213);
    address internal constant SU_HASH_PRECOMPILE = address(0x0214);

    // ---------------------------------------------------------------------
    // Binding hash
    // ---------------------------------------------------------------------

    /// @notice Compute the off-chain ↔ on-chain binding hash for a tribute
    ///         draft. Mirrors `pso_protocol::binding::compute_binding_hash`
    ///         byte-for-byte.
    ///
    /// @param  sender         The EVM address binding the proof (typically
    ///                        `msg.sender` of the verifying contract).
    /// @param  tributeDraftId The TD id being bound (as `uint256`).
    /// @param  chainId        The chain id of the verifying network.
    /// @return The 32-byte BN254 Fr digest, big-endian.
    function computeBindingHash(
        address sender,
        uint256 tributeDraftId,
        uint256 chainId
    ) internal view returns (bytes32) {
        // Implemented as a precompile call in phase 2 of the
        // pso-protocol-extraction migration. The Solidity surface is
        // declared here so dependent contracts can be written against the
        // final shape, but the precompile body lands once `0x0210` is
        // registered in pso-chain.
        sender;
        tributeDraftId;
        chainId;
        revert PsoProtocolPrecompileFailed(BINDING_HASH_PRECOMPILE);
    }

    // ---------------------------------------------------------------------
    // Entity hashes — TributeDraft
    // ---------------------------------------------------------------------

    /// @notice Compute the TributeDraft id: `Poseidon2(owner, worldwideDay)`.
    function computeTributeDraftId(
        bytes32 owner,
        uint64 worldwideDay
    ) internal view returns (bytes32) {
        owner;
        worldwideDay;
        revert PsoProtocolPrecompileFailed(TD_ID_PRECOMPILE);
    }

    /// @notice Compute the TributeDraft entity hash.
    function computeTributeDraftHash(
        bytes32 id,
        uint16 currency,
        uint64 base,
        uint128 atto,
        bytes32[] memory suIds
    ) internal view returns (bytes32) {
        id;
        currency;
        base;
        atto;
        suIds;
        revert PsoProtocolPrecompileFailed(TD_HASH_PRECOMPILE);
    }

    // ---------------------------------------------------------------------
    // Entity hashes — SpendingUnit
    // ---------------------------------------------------------------------

    /// @notice Compute the SpendingUnit id.
    function computeSpendingUnitId(
        bytes32 owner,
        uint64 worldwideDay
    ) internal view returns (bytes32) {
        owner;
        worldwideDay;
        revert PsoProtocolPrecompileFailed(SU_ID_PRECOMPILE);
    }

    /// @notice Compute the SpendingUnit entity hash.
    function computeSpendingUnitHash(
        bytes32 id,
        bytes32 owner,
        uint64 worldwideDay,
        uint16 currency,
        uint64 base,
        uint128 atto,
        bytes32[] memory spendingRecordFingerprints,
        bytes32[] memory amendmentRecordFingerprints
    ) internal view returns (bytes32) {
        id;
        owner;
        worldwideDay;
        currency;
        base;
        atto;
        spendingRecordFingerprints;
        amendmentRecordFingerprints;
        revert PsoProtocolPrecompileFailed(SU_HASH_PRECOMPILE);
    }
}
