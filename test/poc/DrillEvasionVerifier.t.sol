// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe} from "@safe-global/safe-smart-account/Safe.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

/// @dev Ordering probe: it returns magic only while its identity is not burnt.
///      Production verifiers are restricted by operator policy to the pinned,
///      closed-world implementations shipped with the repository. This probe is
///      retained solely to pin the verify-before-burn execution order.
contract BurnAwareOrderingVerifier is IERC7913SignatureVerifier {
    Lockdown private immutable LOCKDOWN;
    address private immutable SAFE;

    constructor(Lockdown lockdown_, address safe_) {
        LOCKDOWN = lockdown_;
        SAFE = safe_;
    }

    function verify(bytes calldata key, bytes32, bytes calldata) external view returns (bytes4) {
        bytes memory signer = abi.encodePacked(address(this), key);
        if (LOCKDOWN.isSignerBurntPermanently(SAFE, signer)) return bytes4(0);
        return IERC7913SignatureVerifier.verify.selector;
    }
}

/// @notice Regression proof for the verify-before-burn ordering in SPEC_V1 §5.2.
/// @dev The probe returns exactly one bytes4 and uses no gas-amplification mechanism.
///      These tests do not expand the production threat model beyond the pinned
///      verifier implementations; they only make the chosen ordering executable.
contract VerifyBeforeBurnRegression is TestEnvironment {
    Safe private safe;
    BurnAwareOrderingVerifier private verifier;
    bytes private signer;

    bytes32 private constant REASON = keccak256("drill-evasion");

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(0xD211);
        verifier = new BurnAwareOrderingVerifier(guard, address(safe));
        signer = abi.encodePacked(address(verifier), bytes32("registered-key"));

        vm.prank(address(safe));
        guard.addLockdownSigner(signer);
    }

    function _rawTrigger(Safe safe_, bytes memory signer_, uint256 gasCap)
        private
        returns (bool ok, bytes memory ret, uint256 gasUsed)
    {
        bytes memory payload =
            abi.encodeCall(Lockdown.triggerLockdown, (address(safe_), REASON, signer_, bytes("proof")));
        uint256 gasBefore = gasleft();
        (ok, ret) = address(guard).call{gas: gasCap}(payload);
        gasUsed = gasBefore - gasleft();
    }

    function _newProbe(uint256 salt) private returns (Safe safe_, bytes memory signer_) {
        safe_ = _createConfigureAndInitialise(salt);
        BurnAwareOrderingVerifier verifier_ = new BurnAwareOrderingVerifier(guard, address(safe_));
        signer_ = abi.encodePacked(address(verifier_), bytes32("registered-key"));
        vm.prank(address(safe_));
        guard.addLockdownSigner(signer_);
    }

    function test_regression_testSignerObservesPreBurnState() public view {
        assertTrue(guard.testSigner(signer, bytes32("drill-hash"), bytes("proof")), "drill says ready");
        assertTrue(guard.isLockdownSigner(address(safe), signer), "identity registered during drill");
        assertFalse(guard.isSignerBurntPermanently(address(safe), signer), "identity not burnt during drill");
    }

    function test_regression_burnAwareVerifierCannotDistinguishDrillFromRealTrigger() public {
        (bool ok, bytes memory ret, uint256 gasUsed) = _rawTrigger(safe, signer, 500_000);
        assertTrue(ok, string(ret));
        assertLt(gasUsed, 200_000, "bounded ordering probe cost");
    }

    function test_control_honestSignerStillBurnsExactlyOnceAfterVerification() public {
        guard.triggerLockdown(address(safe), REASON, signer, bytes("proof"));
        assertFalse(guard.isLockdownSigner(address(safe), signer), "identity consumed");
        assertTrue(guard.isSignerBurntPermanently(address(safe), signer), "identity permanently burnt");
        assertEq(guard.getLockdownSignerCount(address(safe)), 1, "only the fixture signer remains");
    }

    function test_regression_successfulTriggerLocksSafe() public {
        guard.triggerLockdown(address(safe), REASON, signer, bytes("proof"));
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "Safe locked");
    }

    function test_regression_orderingVerdictDoesNotDependOnReasonableGasCap() public {
        uint256[3] memory caps = [uint256(500_000), 2_000_000, 30_000_000];
        for (uint256 i = 0; i < caps.length; ++i) {
            (Safe safe_, bytes memory signer_) = _newProbe(0xD220 + i);
            (bool ok, bytes memory ret, uint256 gasUsed) = _rawTrigger(safe_, signer_, caps[i]);
            assertTrue(ok, string(ret));
            assertLt(gasUsed, 200_000, "bounded ordering probe cost");
        }
    }

    function test_control_honestSignerStillTriggersWithVerifyBeforeBurn() public {
        bytes memory honestSigner = abi.encodePacked(panicKey);
        bytes memory honestSignature = _signTrigger(safe, PANIC_PK, REASON);

        guard.triggerLockdown(address(safe), REASON, honestSigner, honestSignature);

        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "honest trigger locks");
        assertFalse(guard.isLockdownSigner(address(safe), honestSigner), "honest identity consumed");
        assertTrue(guard.isSignerBurntPermanently(address(safe), honestSigner), "honest identity burnt");
    }
}
