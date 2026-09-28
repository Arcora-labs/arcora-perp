// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "../test/utils/MiniTest.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";

interface RealProofVm {
    function getCode(string calldata artifactPath) external view returns (bytes memory);
    function envBytes(string calldata name) external view returns (bytes memory);
    function envBytes32(string calldata name) external view returns (bytes32);
}

interface RealSP1Verifier is ISP1Verifier {
    function VERSION() external pure returns (string memory);
    function VERIFIER_HASH() external pure returns (bytes32);
    function VK_ROOT() external pure returns (bytes32);
}

interface RealSP1Gateway is ISP1Verifier {
    function addRoute(address verifier) external;
    function freezeRoute(bytes4 selector) external;
    function routes(bytes4 selector) external view returns (address verifier, bool frozen);
}

/// Deploy upstream's separately compiled 0.8.20 creation bytecode into this fresh
/// 0.8.24 Foundry EVM. No fork, RPC, broadcast, mock verifier, or source rewriting.
abstract contract RealSP1TestBase is MiniTest {
    RealProofVm internal constant realVm = RealProofVm(address(vm));
    bytes32 internal constant VERIFIER_HASH = 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696;
    bytes32 internal constant VK_ROOT = 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352;
    bytes4 internal constant SELECTOR = bytes4(VERIFIER_HASH);

    RealSP1Verifier internal realVerifier;
    RealSP1Gateway internal realGateway;

    function setUp() public virtual {
        realVerifier =
            RealSP1Verifier(_deploy(realVm.getCode("out/sp1-upstream/SP1VerifierGroth16.sol/SP1Verifier.json")));
        realGateway = _newGateway();
        realGateway.addRoute(address(realVerifier));
    }

    function _newGateway() internal returns (RealSP1Gateway) {
        return RealSP1Gateway(
            _deploy(
                abi.encodePacked(
                    realVm.getCode("out/sp1-upstream/SP1VerifierGateway.sol/SP1VerifierGateway.json"),
                    abi.encode(address(this))
                )
            )
        );
    }

    function _adapter(RealSP1Gateway gateway_, bytes32 vkey) internal returns (SP1ZkVerifier) {
        return new SP1ZkVerifier(ISP1Verifier(address(gateway_)), vkey);
    }

    function _deploy(bytes memory creationCode) private returns (address deployed) {
        require(creationCode.length != 0, "upstream creation bytecode is required");
        assembly ("memory-safe") {
            deployed := create(0, add(creationCode, 32), mload(creationCode))
        }
        require(deployed.code.length != 0, "upstream verifier deployment failed");
    }
}
