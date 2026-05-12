// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PsoProtocol} from "./PsoProtocol.sol";

/// @title PsoProtocolTest
/// @notice Smoke tests for the Solidity binding. Real cross-side equality
///         checks (Rust vs Solidity precompile-call) live in
///         `tests/cross_side_equality.rs` — they spin up a revm instance
///         that exposes the pso-protocol precompiles and assert byte
///         identity.
///
///         These Foundry tests use `vm.mockCall` to stub the precompile
///         response, so they verify the wrapper's calldata-encoding and
///         return-decoding without needing a real precompile host.
contract PsoProtocolTest is Test {
    function testBindingHashWrapperRevertsWithoutPrecompile() public {
        // Without a mockCall, the precompile address returns nothing on
        // standard Foundry chains, so the wrapper should revert with the
        // typed error.
        vm.expectRevert(
            abi.encodeWithSelector(
                PsoProtocol.PsoProtocolPrecompileFailed.selector,
                PsoProtocol.BINDING_HASH_PRECOMPILE
            )
        );
        PsoProtocol.computeBindingHash(address(this), 1, 1);
    }
}
