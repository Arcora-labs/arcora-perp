// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest, Vm} from "./utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Stateful invariant for the inclusion-challenge game (validates the P2 fix).
///
/// The handler is the (honest) sequencer. It settles batches, opens challenges with
/// genuine enclave-signed receipts, and answers them. Settlement is async — a
/// challenge may be opened before OR after the order's batch settles — which is
/// exactly the condition P2 was about. The invariant: an honest answer for a
/// genuinely-included, settled, still-in-window order is NEVER rejected. Before the
/// P2 fix (batch had to predate the challenge) this would be violated whenever the
/// order settled after a same-block challenge.
contract Handler {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    uint256 internal constant K = 16;

    DarkPerpSettlement public s;
    uint256 public challengeBond;

    bytes32 internal root;
    uint256 public nextToSettle;
    mapping(uint256 => bool) public challenged;
    uint256 public answered;
    /// Set true iff a legitimate in-window answer for a settled, included order was
    /// rejected — i.e. the honest sequencer was griefed. MUST stay false.
    bool public griefed;

    function init(DarkPerpSettlement _s, bytes32 genesis, uint256 _bond) external {
        require(address(s) == address(0), "init once");
        s = _s;
        root = genesis;
        challengeBond = _bond;
    }

    function orderHash(uint256 j) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("order", j));
    }

    /// Settle the next order's batch in sequence (each order j lands in batch j).
    function actSettle() external {
        uint256 j = nextToSettle;
        if (j >= K) return;
        bytes32 prev = root;
        bytes32 newRoot = keccak256(abi.encodePacked(prev, j));
        bytes32 manifest = keccak256(abi.encodePacked("m", j));
        bytes32 orderedRoot = s.inclusionLeaf(j, orderHash(j));
        bytes memory proof =
            abi.encode(s.publicCommitment(prev, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0)));
        s.settleBatch(prev, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0), proof);
        root = newRoot;
        nextToSettle = j + 1;
    }

    /// A user opens a challenge for order `seed % K` with a real enclave receipt.
    function actChallenge(uint256 seed) external {
        uint256 j = seed % K;
        if (challenged[j]) return;
        bytes32 digest = s.receiptDigest(orderHash(j), uint64(j), 1, uint64(j));
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        try s.challengeInclusion{value: challengeBond}(orderHash(j), uint64(j), 1, uint64(j), v, r, sig) {
            challenged[j] = true;
        } catch {
            // a duplicate / racing challenge can revert; not our concern here
        }
    }

    /// The honest sequencer answers a settled, in-window challenge.
    function actAnswer(uint256 seed) external {
        uint256 j = seed % K;
        if (!challenged[j]) return;
        if (j >= nextToSettle) return; // not yet settled; the sequencer answers later
        (,,, uint256 deadline,, bool open) = s.challenges(orderHash(j));
        if (!open) return; // already answered
        if (block.number > deadline) return; // expired — a legitimate timeout, not a grief
        bytes32[] memory empty = new bytes32[](0);
        try s.answerChallenge(orderHash(j), j, empty) {
            answered++;
        } catch {
            // a genuinely included, settled, in-window order MUST be answerable
            griefed = true;
        }
    }

    /// Advance time within the window so settle/challenge/answer interleave.
    function actRoll(uint256 n) external {
        vm.roll(block.number + (n % 20) + 1);
    }

    receive() external payable {}
}

contract SettlementInvariantTest is MiniTest {
    DarkPerpSettlement internal s;
    MockZkVerifier internal verifier;
    Handler internal handler;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    uint256 internal constant CHALLENGE_BOND = 1 ether;

    function setUp() public {
        verifier = new MockZkVerifier();
        handler = new Handler();
        // a large challenge window so in-window answers dominate; the honest
        // sequencer is the handler.
        s = new DarkPerpSettlement(
            address(handler),
            vm.addr(ENCLAVE_PK),
            verifier,
            GENESIS,
            100_000,
            1_000,
            CHALLENGE_BOND,
            0,
            address(handler),
            0
        );
        handler.init(s, GENESIS, CHALLENGE_BOND);
        vm.deal(address(handler), 1000 ether);
    }

    function targetContracts() public view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(handler);
    }

    /// The honest sequencer is never griefed: every in-window answer for a settled,
    /// genuinely-included order succeeds (this is the P2 property).
    function invariant_honest_sequencer_is_never_griefed() public view {
        assertTrue(!handler.griefed(), "honest answer rejected - P2 grief regression");
    }

    /// And it is never slashed (the fuzzer drives only honest handler actions; no
    /// challenge is left unanswered past its deadline by the sequencer itself).
    function invariant_honest_sequencer_not_slashed() public view {
        assertTrue(!s.slashed(), "honest sequencer slashed");
    }
}
