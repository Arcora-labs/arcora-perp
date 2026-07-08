// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";

/// Cheatcodes the Deploy env-override test needs beyond MiniTest's Vm subset
/// (same well-known cheatcode address; dispatched by selector).
interface VmExt {
    function setEnv(string calldata name, string calldata value) external;
    function chainId(uint256 newChainId) external;
    function toString(address value) external pure returns (string memory);
}

/// Live-migration Task 0: `VERIFIER` env override in Deploy.s.sol.
/// Set  -> the given (real, e.g. SP1) verifier is bound; no Mock, no Mock guard.
/// Zero -> a fresh MockZkVerifier is deployed, gated by the DP-007 testnet guard.
///
/// NOTE: all branches live in ONE test function on purpose — `vm.setEnv` mutates
/// the (process-global) env while forge runs test functions in parallel, so
/// splitting the branches into separate tests would race on `VERIFIER`.
contract DeployVerifierEnvTest is MiniTest {
    VmExt internal constant vmx = VmExt(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function test_verifier_env_override() public {
        address fake = 0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF;
        vmx.setEnv("ALLOW_MOCK_VERIFIER", "0"); // don't inherit a stray shell override

        // 1) VERIFIER set -> binds the given address; no Mock deployed.
        vmx.setEnv("VERIFIER", vmx.toString(fake));
        (DarkPerpSettlement s1,, IZkVerifier v1,) = (new Deploy()).run();
        assertEq(address(v1), fake, "VERIFIER env must bind the given verifier");
        assertEq(address(s1.verifier()), fake, "settlement must be wired to the env verifier");

        // 2) VERIFIER zero -> a fresh non-zero MockZkVerifier (today's behavior).
        vmx.setEnv("VERIFIER", vmx.toString(address(0)));
        (DarkPerpSettlement s2,, IZkVerifier v2,) = (new Deploy()).run();
        assertTrue(address(v2) != address(0), "zero VERIFIER must deploy a Mock verifier");
        assertTrue(address(v2) != fake, "Mock branch must not reuse the env address");
        assertTrue(address(v2).code.length > 0, "Mock verifier must be a deployed contract");
        assertEq(address(s2.verifier()), address(v2), "settlement must be wired to the Mock");

        // 3) DP-007 guard only fires on the Mock branch: on a non-testnet chain,
        //    zero VERIFIER refuses...
        vmx.chainId(1);
        Deploy d3 = new Deploy();
        vm.expectRevert(
            bytes(
                "Deploy: MockZkVerifier is unsound; refusing on a non-testnet chain (set ALLOW_MOCK_VERIFIER=1 to override, UNSAFE)"
            )
        );
        d3.run();

        // 4) ...while a real VERIFIER deploys guard-free even there.
        vmx.setEnv("VERIFIER", vmx.toString(fake));
        (DarkPerpSettlement s4,, IZkVerifier v4,) = (new Deploy()).run();
        assertEq(address(v4), fake, "real VERIFIER needs no Mock guard on mainnet");
        assertEq(address(s4.verifier()), fake, "settlement wired to the real verifier on mainnet");
    }
}
