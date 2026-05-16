// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PsoProtocol} from "./PsoProtocol.sol";

/// @title PsoProtocolTest
/// @notice Smoke tests for the Solidity binding. The real Rust ↔ Solidity
///         byte-equality check lives in `tests/cross_side_equality.rs` —
///         it spins up a revm instance that exposes the pso-protocol
///         precompiles and asserts identity.
///
///         These Foundry tests use `vm.mockCall` to stub the precompile
///         responses, so they verify the wrapper's calldata-encoding and
///         return-decoding without needing a real precompile host.
contract PsoProtocolTest is Test {
    /// Encoded input the wrapper must send to `0x0210`:
    /// `abi.encodePacked(uint256(uint160(sender)), tdid, chainId)` = 96 bytes.
    function _expectedBindingInput(address sender, uint256 tdid, uint256 chainId)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint256(uint160(sender)), tdid, chainId);
    }

    /// `external` thunk so revert-expecting tests can drive the library
    /// through a real call boundary. `PsoProtocol.computeBindingHash` is
    /// `internal` (library-inlined), so `vm.expectRevert` cannot observe
    /// the revert when the test contract calls it directly — the revert
    /// happens inside the same call frame as the test itself.
    function externalComputeBindingHash(address sender, uint256 tdid, uint256 chainId)
        external
        view
        returns (bytes32)
    {
        return PsoProtocol.computeBindingHash(sender, tdid, chainId);
    }

    function test_bindingHash_wrapper_passes_correct_input_and_returns_precompile_output() public {
        address sender = address(0xCafe);
        uint256 tdid = uint256(0x1234567890abcdef);
        uint256 chainId = 31_337;

        bytes memory expectedInput = _expectedBindingInput(sender, tdid, chainId);
        bytes32 expectedOut = bytes32(uint256(0xfeedface));

        vm.mockCall(PsoProtocol.BINDING_HASH_PRECOMPILE, expectedInput, abi.encode(expectedOut));

        bytes32 got = PsoProtocol.computeBindingHash(sender, tdid, chainId);
        assertEq(got, expectedOut, "wrapper did not return precompile output unchanged");
    }

    function test_bindingHash_wrapper_reverts_when_precompile_returns_wrong_length() public {
        address sender = address(0xCafe);
        uint256 tdid = 1;
        uint256 chainId = 1;

        vm.mockCall(
            PsoProtocol.BINDING_HASH_PRECOMPILE,
            _expectedBindingInput(sender, tdid, chainId),
            // 31 bytes — wrong length.
            hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                PsoProtocol.PsoProtocolPrecompileFailed.selector,
                PsoProtocol.BINDING_HASH_PRECOMPILE
            )
        );
        this.externalComputeBindingHash(sender, tdid, chainId);
    }
}
