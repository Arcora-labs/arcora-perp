// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BatchClockAnchorPrototype as Clock} from "../src/BatchClockAnchorPrototype.sol";

interface ClockTestVm {
    function warp(uint256) external;
    function prank(address) external;
    function expectRevert(bytes4) external;
    function chainId(uint256) external;
}

contract BatchClockAnchorPrototypeTest {
    ClockTestVm constant vm = ClockTestVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Clock clock;
    bytes32 constant ROOT = bytes32(uint256(11));
    bytes32 constant MANIFEST = bytes32(uint256(22));
    uint64 constant FIRST = 1_000_000;
    uint64 constant LAST = 1_008_000;

    function setUp() public {
        vm.warp(1008);
        clock = new Clock(address(this), 10_000, 2_000);
    }

    function test_records_execution_context_before_proving() public {
        bytes32 commitment = clock.register(0, ROOT, MANIFEST, FIRST, LAST);
        Clock.Anchor memory a = clock.getAnchor(0, ROOT);
        require(a.exists && a.commitment == commitment, "missing exact receipt");
        require(a.anchoredAtMs == LAST, "chain time not recorded");
    }

    function test_delayed_proof_does_not_expire_or_restamp_receipt() public {
        bytes32 commitment = clock.register(0, ROOT, MANIFEST, FIRST, LAST);
        vm.warp(1008 + 7 days);
        require(clock.getAnchor(0, ROOT).commitment == commitment, "receipt changed after delay");
        require(clock.register(0, ROOT, MANIFEST, FIRST, LAST) == commitment, "retry refreshed anchor");
        require(clock.getAnchor(0, ROOT).anchoredAtMs == LAST, "original chain time changed");
    }

    function test_rejects_backdating_beyond_skew() public {
        vm.expectRevert(Clock.Backdated.selector);
        clock.register(0, ROOT, MANIFEST, FIRST - 2001, LAST - 2001);
    }

    function test_rejects_future_dating_beyond_skew() public {
        vm.expectRevert(Clock.FutureDated.selector);
        clock.register(0, ROOT, MANIFEST, FIRST + 2001, LAST + 2001);
    }

    function test_accepts_exact_clock_skew_boundaries() public {
        clock.register(0, ROOT, MANIFEST, FIRST - 2000, LAST - 2000);
        clock.register(1, ROOT, MANIFEST, FIRST + 2000, LAST + 2000);
    }

    function test_rejects_reversed_range() public {
        vm.expectRevert(Clock.InvalidRange.selector);
        clock.register(0, ROOT, MANIFEST, LAST + 1, LAST);
    }

    function test_rejects_overlong_window() public {
        vm.expectRevert(Clock.InvalidRange.selector);
        clock.register(0, ROOT, MANIFEST, LAST - 10_001, LAST);
    }

    function test_wrong_caller_cannot_register_or_retry() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(Clock.Unauthorized.selector);
        clock.register(0, ROOT, MANIFEST, FIRST, LAST);
        clock.register(0, ROOT, MANIFEST, FIRST, LAST);
        vm.prank(address(0xBAD));
        vm.expectRevert(Clock.Unauthorized.selector);
        clock.register(0, ROOT, MANIFEST, FIRST, LAST);
    }

    function test_changed_manifest_cannot_replace_existing_anchor() public {
        bytes32 commitment = clock.register(0, ROOT, MANIFEST, FIRST, LAST);
        vm.expectRevert(Clock.ReplacementForbidden.selector);
        clock.register(0, ROOT, bytes32(uint256(23)), FIRST, LAST);
        require(clock.getAnchor(0, ROOT).commitment == commitment, "failed replacement mutated state");
    }

    function test_changed_time_cannot_replace_existing_anchor() public {
        clock.register(0, ROOT, MANIFEST, FIRST, LAST);
        vm.expectRevert(Clock.ReplacementForbidden.selector);
        clock.register(0, ROOT, MANIFEST, FIRST + 1, LAST);
    }

    function test_domain_binds_chain_contract_batch_and_previous_root() public {
        bytes32 a = clock.register(0, ROOT, MANIFEST, FIRST, LAST);
        require(clock.register(1, ROOT, MANIFEST, FIRST, LAST) != a, "batch not bound");
        require(clock.register(0, bytes32(uint256(12)), MANIFEST, FIRST, LAST) != a, "root not bound");
        Clock other = new Clock(address(this), 10_000, 2_000);
        require(other.register(0, ROOT, MANIFEST, FIRST, LAST) != a, "contract not bound");
        vm.chainId(block.chainid + 1);
        require(clock.register(0, ROOT, MANIFEST, FIRST, LAST) != a, "chain not bound");
    }

    function test_missing_anchor_is_not_an_empty_valid_receipt() public {
        vm.expectRevert(Clock.MissingAnchor.selector);
        clock.getAnchor(0, ROOT);
    }

    function test_rejects_timestamp_conversion_overflow() public {
        vm.warp(uint256(type(uint64).max) / 1000 + 1);
        vm.expectRevert(Clock.TimeOverflow.selector);
        clock.register(0, ROOT, MANIFEST, FIRST, LAST);
    }

    function test_rejects_invalid_coordinator_configuration() public {
        vm.expectRevert(Clock.InvalidConfiguration.selector);
        new Clock(address(0), 10_000, 2_000);
        vm.expectRevert(Clock.InvalidConfiguration.selector);
        new Clock(address(this), 0, 2_000);
    }

    function test_fixed_encoding_vector_matches_rust() public pure {
        bytes32 domain = keccak256("arcora:batch-clock-anchor:prototype:v1");
        require(domain == 0xa45aa03554e9127f800c61cc9d9bb4cdd303becd1f3e4e9e6f0fcb9c390104f2, "domain vector");
        bytes32 key = keccak256(
            abi.encode(
                domain,
                uint256(84532),
                address(0x1111111111111111111111111111111111111111),
                uint64(7),
                bytes32(0x2222222222222222222222222222222222222222222222222222222222222222)
            )
        );
        require(key == 0x0e791057196a63b166928fc9de3e66da9f43a305b1046362f1b174eafd712371, "key vector");
        bytes32 content = keccak256(
            abi.encode(
                bytes32(0x3333333333333333333333333333333333333333333333333333333333333333),
                uint64(1700000000000),
                uint64(1700000008000)
            )
        );
        require(content == 0x96afa7383dee3597dd343ceccddac7d1bf4bc39dac9e0348bced647368152d8c, "content vector");
        require(
            keccak256(abi.encode(domain, key, content, uint64(1700000008000)))
                == 0xd92348d70cb007574825881e4dc5d21d66f49a084ec2b2410572a7c5ea49fb6f,
            "commitment vector"
        );
    }
}
