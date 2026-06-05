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

    /// Encoded input the wrapper must send to `0x0211`:
    /// `abi.encodePacked(id, uint256(currency), uint256(base), uint256(atto), suIds)`.
    /// Total length is `128 + 32 * suIds.length` bytes — the precompile derives
    /// `N` from `(input.length - 128) / 32`, so no explicit length slot.
    ///
    /// `suIds` is passed directly (rather than via `_packBytes32Array`, which is
    /// `private` to the library) so this helper is an independent transcription
    /// of the documented layout, not a copy of the wrapper's encoding call.
    function _expectedTdInput(
        bytes32 id,
        uint16 currency,
        uint64 amountBase,
        uint64 amountAtto,
        bytes32[] memory suIds
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            id, uint256(currency), uint256(amountBase), uint256(amountAtto), suIds
        );
    }

    /// Encoded input the wrapper must send to `0x0212`:
    /// `abi.encodePacked(id, owner, uint256(wwd), uint256(currency),`
    /// `   uint256(base), uint256(atto), uint256(sr.length), srFps,`
    /// `   uint256(ar.length), arFps)`.
    ///
    /// Both count slots are mandatory — SR and AR enter the iterated hash chain
    /// at different points, so the precompile cannot infer the boundary from
    /// total length alone.
    function _expectedSuInput(
        bytes32 id,
        bytes32 owner,
        address attester,
        address referrer,
        uint64 worldwideDay,
        uint16 currency,
        uint64 amountBase,
        uint64 amountAtto,
        bytes32[] memory srFps,
        bytes32[] memory arFps
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            id,
            owner,
            uint256(uint160(attester)),
            uint256(uint160(referrer)),
            uint256(worldwideDay),
            uint256(currency),
            uint256(amountBase),
            uint256(amountAtto),
            uint256(srFps.length),
            srFps,
            uint256(arFps.length),
            arFps
        );
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

    function test_tributeDraftHash_wrapper_passes_correct_input_and_returns_precompile_output()
        public
    {
        bytes32 id = bytes32(uint256(0xbeef));
        uint16 currency = 840;
        uint64 amountBase = 500;
        uint64 amountAtto = 1;

        bytes32[] memory suIds = new bytes32[](3);
        suIds[0] = bytes32(uint256(0x1001));
        suIds[1] = bytes32(uint256(0x1002));
        suIds[2] = bytes32(uint256(0x1003));

        bytes memory expectedInput = _expectedTdInput(id, currency, amountBase, amountAtto, suIds);
        bytes32 expectedOut = bytes32(uint256(0xdeadbeef));

        vm.mockCall(PsoProtocol.TD_HASH_PRECOMPILE, expectedInput, abi.encode(expectedOut));

        bytes32 got =
            PsoProtocol.computeTributeDraftHash(id, currency, amountBase, amountAtto, suIds);
        assertEq(got, expectedOut, "TD wrapper did not return precompile output unchanged");
    }

    function test_spendingUnitHash_wrapper_passes_correct_input_and_returns_precompile_output()
        public
    {
        bytes32 id = bytes32(uint256(0xc0de));
        bytes32 owner = bytes32(uint256(0xf00d));
        address attester = address(0x5A);
        address referrer = address(0x7A11E7);
        uint64 worldwideDay = 100;
        uint16 currency = 978;
        uint64 amountBase = 50;
        uint64 amountAtto = 42;

        bytes32[] memory srFps = new bytes32[](2);
        srFps[0] = bytes32(uint256(2000));
        srFps[1] = bytes32(uint256(2001));

        bytes32[] memory arFps = new bytes32[](3);
        arFps[0] = bytes32(uint256(3000));
        arFps[1] = bytes32(uint256(3001));
        arFps[2] = bytes32(uint256(3002));

        bytes memory expectedInput = _expectedSuInput(
            id, owner, attester, referrer, worldwideDay, currency, amountBase, amountAtto, srFps, arFps
        );
        bytes32 expectedOut = bytes32(uint256(0xfacefeed));

        vm.mockCall(PsoProtocol.SU_HASH_PRECOMPILE, expectedInput, abi.encode(expectedOut));

        bytes32 got = PsoProtocol.computeSpendingUnitHash(
            id, owner, attester, referrer, worldwideDay, currency, amountBase, amountAtto, srFps, arFps
        );
        assertEq(got, expectedOut, "SU wrapper did not return precompile output unchanged");
    }
}
