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

/// Env overrides in Deploy.s.sol.
/// `VERIFIER` (live-migration Task 0):
///   Set  -> the given (real, e.g. SP1) verifier is bound; no Mock, no Mock guard.
///   Zero -> a fresh MockZkVerifier is deployed, gated by the DP-007 testnet guard.
/// `PRIVATE_KEY` / `GATEWAY_SIGNER`: defaults exist only on the local anvil chain; any
/// other chain needs both set explicitly and refuses the default anvil accounts.
///
/// NOTE: all branches live in ONE test function on purpose — `vm.setEnv` mutates
/// the (process-global) env while forge runs test functions in parallel, so
/// splitting the branches into separate tests would race on the shared variables.
contract DeployVerifierEnvTest is MiniTest {
    VmExt internal constant vmx = VmExt(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // Anvil's well-known keys #0 and #9 and address #1: public test material.
    string internal constant ANVIL_PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    string internal constant ANVIL_PK9 = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
    address internal constant ANVIL_ADDR0 = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address internal constant ANVIL_ADDR1 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    // A throwaway key that is not one of the default anvil accounts.
    string internal constant OPERATOR_PK = "0x000000000000000000000000000000000000000000000000000000000000beef";

    function test_deploy_env_overrides() public {
        address fake = 0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF;
        address realSigner = 0x1111111111111111111111111111111111111111;
        // don't inherit stray shell overrides
        vmx.setEnv("ALLOW_MOCK_VERIFIER", "0");
        vmx.setEnv("ALLOW_PUBLIC_DEV_KEYS", "0");
        vmx.setEnv("PRIVATE_KEY", "0");
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(address(0)));

        // 1) VERIFIER set -> binds the given address; no Mock deployed.
        vmx.setEnv("VERIFIER", vmx.toString(fake));
        (DarkPerpSettlement s1, CollateralVault vault1, IZkVerifier v1,) = (new Deploy()).run();
        assertEq(address(v1), fake, "VERIFIER env must bind the given verifier");
        assertEq(address(s1.verifier()), fake, "settlement must be wired to the env verifier");
        // local anvil chain: the simulation defaults stay available
        assertEq(s1.sequencer(), ANVIL_ADDR0, "local simulation defaults to the anvil deployer");
        assertEq(vault1.gatewaySigner(), ANVIL_ADDR0, "local simulation defaults GATEWAY_SIGNER to the sequencer");

        // 2) VERIFIER zero -> a fresh non-zero MockZkVerifier (today's behavior).
        vmx.setEnv("VERIFIER", vmx.toString(address(0)));
        (DarkPerpSettlement s2,, IZkVerifier v2,) = (new Deploy()).run();
        assertTrue(address(v2) != address(0), "zero VERIFIER must deploy a Mock verifier");
        assertTrue(address(v2) != fake, "Mock branch must not reuse the env address");
        assertTrue(address(v2).code.length > 0, "Mock verifier must be a deployed contract");
        assertEq(address(s2.verifier()), address(v2), "settlement must be wired to the Mock");

        // 3) Off the local chain the deployer and gateway signer are mandatory, and every
        //    default anvil account is refused for both.
        vmx.chainId(1);
        Deploy d3 = new Deploy();
        vm.expectRevert(bytes("Deploy: PRIVATE_KEY is required off the local anvil chain"));
        d3.run();
        vmx.setEnv("PRIVATE_KEY", ANVIL_PK0);
        vm.expectRevert(bytes("Deploy: PRIVATE_KEY is a public anvil account key"));
        d3.run();
        vmx.setEnv("PRIVATE_KEY", ANVIL_PK9);
        vm.expectRevert(bytes("Deploy: PRIVATE_KEY is a public anvil account key"));
        d3.run();
        vmx.setEnv("PRIVATE_KEY", OPERATOR_PK);
        vm.expectRevert(bytes("Deploy: GATEWAY_SIGNER is required off the local anvil chain"));
        d3.run();
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(ANVIL_ADDR0));
        vm.expectRevert(bytes("Deploy: GATEWAY_SIGNER is a public anvil account"));
        d3.run();
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(ANVIL_ADDR1));
        vm.expectRevert(bytes("Deploy: GATEWAY_SIGNER is a public anvil account"));
        d3.run();
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(realSigner));

        // 4) DP-007 guard only fires on the Mock branch: on a non-testnet chain,
        //    zero VERIFIER refuses...
        vm.expectRevert(
            bytes(
                "Deploy: MockZkVerifier is unsound; refusing on a non-testnet chain (set ALLOW_MOCK_VERIFIER=1 to override, UNSAFE)"
            )
        );
        d3.run();

        // 5) ...while a real VERIFIER deploys guard-free even there, with the explicit signer.
        vmx.setEnv("VERIFIER", vmx.toString(fake));
        (DarkPerpSettlement s5, CollateralVault vault5, IZkVerifier v5,) = (new Deploy()).run();
        assertEq(address(v5), fake, "real VERIFIER needs no Mock guard on mainnet");
        assertEq(address(s5.verifier()), fake, "settlement wired to the real verifier on mainnet");
        assertEq(vault5.gatewaySigner(), realSigner, "vault pins the explicit GATEWAY_SIGNER");

        // 6) A fork dry run may opt in to the public keys explicitly.
        vmx.setEnv("PRIVATE_KEY", ANVIL_PK0);
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(ANVIL_ADDR0));
        vmx.setEnv("ALLOW_PUBLIC_DEV_KEYS", "1");
        (, CollateralVault vault6,,) = (new Deploy()).run();
        assertEq(vault6.gatewaySigner(), ANVIL_ADDR0, "explicit opt-in accepts the public keys");

        vmx.setEnv("ALLOW_PUBLIC_DEV_KEYS", "0");
        vmx.setEnv("PRIVATE_KEY", "0");
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(address(0)));
    }
}
