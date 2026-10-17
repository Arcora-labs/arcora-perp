// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {ClockBoundVerifier} from "../src/ClockBoundVerifier.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {MockSettlementGate} from "./mocks/MockSettlementGate.sol";

/// Cheatcodes this suite needs beyond the vendored MiniTest subset.
interface CrossLayerVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function etch(address target, bytes calldata newRuntimeBytecode) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function chainId(uint256 newChainId) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// @notice Locks the on-chain hashing to the Rust producers. The expected values
/// come from `crates/prover/tests/vectors.rs` (run there to regenerate). If the
/// Solidity and Rust hashing ever diverge, the on-chain slashing path could never
/// verify a real enclave receipt and proofs could never settle — so this guards
/// the whole cross-layer contract.
///
/// The challenge-authorization and deposit-permit vectors below were computed outside
/// Solidity, with Foundry's `cast` (and re-checked by concatenating the words by hand):
///
///   auth digest  = cast keccak $(cast abi-encode \
///                    "f(bytes32,uint256,address,bytes32,uint64,uint64,uint64,address)" \
///                    <CHALLENGE_AUTH_TAG> 84532 <settlement> <orderHash> <seqNo> <recvTimeMs> \
///                    <batchIdHint> <beneficiary>)
///   permit digest = cast keccak $(cast abi-encode --packed \
///                    "f(bytes32,uint256,address,address,bytes32,uint256,uint256)" \
///                    <DEPOSIT_PERMIT_TAG> 84532 <vault> <from> <ownerCommit> <amount> <validUntil>)
///   signatures   = cast wallet sign --no-hash --private-key <key> <digest>   (r‖s‖v)
///
/// The authorization is signed with the enclave key of `crates/sequencer/tests/fixture.rs`
/// (seed 0x07…07, address 0x4a62…c569); the permit with the gateway's demo signer key
/// (`DEMO_GATEWAY_SIGNER_KEY`, address 0xf39F…2266). Both are RFC 6979 deterministic, so
/// the Rust signers reproduce the same `r‖s‖v`. The permit tuple reuses the gateway's
/// earlier deposit-authorization vector inputs (vault 0x11…, from 0x22…, commit 0x33…,
/// amount 1000) plus `validUntil`.
contract CrossLayerTest is MiniTest {
    CrossLayerVm internal constant xvm = CrossLayerVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    DarkPerpSettlement internal s;

    uint256 internal constant BASE_SEPOLIA = 84532;
    /// Fixed addresses the KATs are computed at (the template is etched there).
    address internal constant KAT_SETTLEMENT = 0x2222222222222222222222222222222222222222;
    address internal constant KAT_VAULT = 0x1111111111111111111111111111111111111111;

    address internal constant RUST_ENCLAVE = 0x4a62316623ad457F02cDC5D997deD67a383EC569;
    bytes32 internal constant RUST_ORDER_HASH = 0x0c1646898f0e7370046e707059dd7cb9eba4b66af66f67671f69101d508231c5;
    address internal constant KAT_BENEFICIARY = 0x3333333333333333333333333333333333333333;

    bytes32 internal constant CHALLENGE_AUTH_TAG_KAT =
        0x69f32c88aac1254085ee4ba164b69f2f12fb02828e83d559eff228842bdcc42a;
    bytes32 internal constant DEPOSIT_PERMIT_TAG_KAT =
        0x64f75800264cb4053b5b671aa4a797e49b39732e10c2ad3768fceffb4b2c0bb4;

    /// Authorization A: the fixture's order (seq 0, recv 1000 ms, hint 0) for
    /// `KAT_BENEFICIARY` at `KAT_SETTLEMENT` on 84532.
    bytes32 internal constant AUTH_A_DIGEST = 0xc97f5f187d95859ac2b5787fc5a2b4aaab47da927688f0b2038e0a03ff6f337d;
    /// Enclave signature over AUTH_A_DIGEST (v = 27).
    bytes internal constant AUTH_A_SIG =
        hex"490ce9b286399686afb9dfb81f58c2fa2622d492fb468f27682b22fc15ed81644c1c3b569abd8431ff2e339bb14d1022a5ef5d58dad371b6cfe314ad28e414821b";
    /// Authorization B: order 0x12…12, seq 7, recv 123456789 ms, hint 3, same beneficiary,
    /// settlement and chain. Every integer field differs, so a field-order slip shows.
    bytes32 internal constant AUTH_B_DIGEST = 0x72e7483a96cc46922628812fa90ac8351fb95784c7883861a34836b14f882225;

    address internal constant PERMIT_FROM = 0x2222222222222222222222222222222222222222;
    bytes32 internal constant PERMIT_COMMIT = 0x3333333333333333333333333333333333333333333333333333333333333333;
    uint256 internal constant PERMIT_AMOUNT = 1000;
    uint64 internal constant PERMIT_VALID_UNTIL = 1_800_000_000;
    bytes32 internal constant PERMIT_DIGEST = 0xb487c678ab8b02ccbd35a03ea1d01c38f0183258f2c23b56f3fb5096096c07cc;
    /// Demo gateway signer signature over PERMIT_DIGEST (v = 28).
    bytes internal constant PERMIT_SIG =
        hex"67b721dee260db90686eebd17d9fc542e190fe4472fba8c3a9bba2863cbe781c4e826942fcd397b7f786a39d0182baf9588e947c0f2c153e08ca326ec25f1d611c";
    address internal constant DEMO_GATEWAY_SIGNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    /// The deposit chain after the permitted deposit (id 0), also from `cast`:
    /// leaf = keccak(from ‖ commit ‖ uint256(1000) ‖ uint256(0)), tip = keccak(0 ‖ leaf).
    bytes32 internal constant PERMIT_DEPOSIT_TIP = 0xfc3a11b391f25a5fd841529b4f9cf4d9b799696ca83139dc3662589dc84a011b;
    /// Storage slot of `CollateralVault.gatewaySigner` (`forge inspect … storageLayout`).
    /// Etching copies code only, so the test writes it and reads it back.
    uint256 internal constant VAULT_GATEWAY_SIGNER_SLOT = 10;

    function setUp() public {
        s = new DarkPerpSettlement(
            SettlementTestConfig.legacy(
                address(this), address(0xE), new MockClockVerifier(), bytes32(0), 100, 50, 0, 0, address(this), 0
            )
        );
    }

    /// A settlement with the launch challenge parameters (0.01 ether stake, 3600 s
    /// inclusion SLA) and the Rust fixture's enclave, etched at `KAT_SETTLEMENT`.
    function _etchedSettlement() internal returns (DarkPerpSettlement d) {
        DarkPerpSettlement template = new DarkPerpSettlement(
            SettlementTestConfig.legacy(
                address(this),
                RUST_ENCLAVE,
                new MockClockVerifier(),
                bytes32(0),
                43_200,
                3_600,
                0.01 ether,
                3_600,
                address(this),
                300
            )
        );
        xvm.etch(KAT_SETTLEMENT, address(template).code);
        d = DarkPerpSettlement(KAT_SETTLEMENT);
    }

    function test_receipt_digest_matches_rust() public view {
        // orderHash = 0x12..12, seq=7, recv=1000, hint=0
        bytes32 d = s.receiptDigest(
            bytes32(uint256(0x1212121212121212121212121212121212121212121212121212121212121212)), 7, 1000, 0
        );
        assertEq(
            d,
            0xea97e0063439108b01114aef8136d5c7f4cad5d900f8a3c3e48cfbc583a4ae24,
            "receipt digest must match perp-core::Receipt::signing_digest"
        );
    }

    /// SEC-019 re-pin: the commitment is now SEVEN words, with the derived
    /// `depositsRoot` appended LAST. The previous expectation
    /// (`0x5fcf2d93…2062`) was the six-word preimage and is stale — the Rust side
    /// (`crates/prover/tests/vectors.rs`) folds the deposit chain into the same
    /// vector, so both layers move together or neither settles.
    function test_public_commitment_matches_rust() public view {
        bytes32 c = s.publicCommitment(
            bytes32(uint256(0x0101010101010101010101010101010101010101010101010101010101010101)),
            bytes32(uint256(0x0202020202020202020202020202020202020202020202020202020202020202)),
            bytes32(uint256(0x0303030303030303030303030303030303030303030303030303030303030303)),
            bytes32(uint256(0x0404040404040404040404040404040404040404040404040404040404040404)),
            bytes32(uint256(0x0505050505050505050505050505050505050505050505050505050505050505)),
            bytes32(uint256(0x0606060606060606060606060606060606060606060606060606060606060606)),
            bytes32(uint256(0x0707070707070707070707070707070707070707070707070707070707070707))
        );
        assertEq(
            c,
            0x27e3e52688359d5759ff4c7b0bea4d25a14b3c81652a4083d531592f827d8902,
            "public commitment must match crates/prover::PublicInputs::commitment"
        );
    }

    /// A receipt SIGNED IN RUST (crates/sequencer, secp256k1) recovers under L1
    /// `ecrecover` to the enclave. Fixture from `crates/sequencer/tests/fixture.rs`. The
    /// receipt digest stays a cross-layer helper; challenges use the separate
    /// authorization below.
    function test_real_rust_receipt_passes_ecrecover() public {
        DarkPerpSettlement d = new DarkPerpSettlement(
            SettlementTestConfig.legacy(
                address(this), RUST_ENCLAVE, new MockClockVerifier(), bytes32(0), 100, 50, 0, 0, address(this), 0
            )
        );
        uint8 v = 28;
        bytes32 r = 0xfb8daee4e013cc0fc4a472efd1ff4acf96719a1325690f4aa714d5c6c0f07704;
        bytes32 sg = 0x797b44171434e2623f60b97ff3bd8975979761b7bce805ab84c6f27bd31bdae1;

        // recover sanity: the digest the contract builds must recover the enclave
        bytes32 digest = d.receiptDigest(RUST_ORDER_HASH, 0, 1000, 0);
        assertEq(ecrecover(digest, v, r, sg), RUST_ENCLAVE, "rust receipt recovers to enclave");
    }

    /// The same Rust receipt signature does not open an inclusion challenge: the
    /// challenge digest is a different, chain- and settlement-bound preimage.
    function test_raw_receipt_signature_is_not_a_challenge_authorization() public {
        DarkPerpSettlement d = new DarkPerpSettlement(
            SettlementTestConfig.legacy(
                address(this), RUST_ENCLAVE, new MockClockVerifier(), bytes32(0), 100, 50, 0, 0, address(this), 0
            )
        );
        bytes memory receiptSig = abi.encodePacked(
            bytes32(0xfb8daee4e013cc0fc4a472efd1ff4acf96719a1325690f4aa714d5c6c0f07704),
            bytes32(0x797b44171434e2623f60b97ff3bd8975979761b7bce805ab84c6f27bd31bdae1),
            uint8(28)
        );
        assertTrue(
            d.challengeAuthDigest(RUST_ORDER_HASH, 0, 1000, 0, address(this))
                != d.receiptDigest(RUST_ORDER_HASH, 0, 1000, 0),
            "distinct digests"
        );
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        d.challengeInclusion(RUST_ORDER_HASH, 0, 1000, 0, address(this), receiptSig);
        (,,,,, bool open) = d.challenges(RUST_ORDER_HASH);
        assertTrue(!open, "no challenge from a raw receipt");
    }

    function test_a06_wind_down_phase_one_commitment_matches_rust() public view {
        bytes32 c = s.windDownCommitment(
            bytes32(uint256(0x0101010101010101010101010101010101010101010101010101010101010101)),
            bytes32(uint256(0x0202020202020202020202020202020202020202020202020202020202020202)),
            bytes32(uint256(0x0303030303030303030303030303030303030303030303030303030303030303)),
            bytes32(uint256(0x0404040404040404040404040404040404040404040404040404040404040404)),
            bytes32(uint256(0x0505050505050505050505050505050505050505050505050505050505050505)),
            bytes32(uint256(0x0606060606060606060606060606060606060606060606060606060606060606)),
            bytes32(uint256(0x0707070707070707070707070707070707070707070707070707070707070707)),
            1
        );
        assertEq(c, 0x10e0f1fecdde1dc0b2aad3f551163ce9ea181ecc40f44d3b935dd11c5c373b88, "Rust phase-1 KAT");
    }

    // --- challenge authorization (enclave-signed, beneficiary-bound) -----------------

    function test_domain_tags_and_abi_version_match_independent_vectors() public {
        assertEq(s.CHALLENGE_AUTH_TAG(), CHALLENGE_AUTH_TAG_KAT, "challenge auth tag");
        assertEq(s.ABI_VERSION(), 3, "abi version");
        MockSettlementGate gate = new MockSettlementGate();
        CollateralVault v = new CollateralVault(address(gate), address(new MockUSDC()), DEMO_GATEWAY_SIGNER);
        assertEq(v.DEPOSIT_PERMIT_TAG(), DEPOSIT_PERMIT_TAG_KAT, "deposit permit tag");
        assertEq(SettlementTestConfig.CHALLENGE_AUTH_TAG, CHALLENGE_AUTH_TAG_KAT, "test helper tag");
        assertEq(SettlementTestConfig.DEPOSIT_PERMIT_TAG, DEPOSIT_PERMIT_TAG_KAT, "test helper tag");
    }

    function test_challenge_auth_digest_kat_at_fixed_settlement() public {
        DarkPerpSettlement d = _etchedSettlement();
        xvm.chainId(BASE_SEPOLIA);
        assertEq(d.challengeAuthDigest(RUST_ORDER_HASH, 0, 1000, 0, KAT_BENEFICIARY), AUTH_A_DIGEST, "authorization A");
        assertEq(
            d.challengeAuthDigest(
                bytes32(uint256(0x1212121212121212121212121212121212121212121212121212121212121212)),
                7,
                123_456_789,
                3,
                KAT_BENEFICIARY
            ),
            AUTH_B_DIGEST,
            "authorization B"
        );
        // The local test helper reproduces the same preimage.
        assertEq(
            SettlementTestConfig.challengeAuthDigest(KAT_SETTLEMENT, RUST_ORDER_HASH, 0, 1000, 0, KAT_BENEFICIARY),
            AUTH_A_DIGEST,
            "helper digest"
        );
        // The digest is bound to the chain.
        xvm.chainId(BASE_SEPOLIA + 1);
        assertTrue(d.challengeAuthDigest(RUST_ORDER_HASH, 0, 1000, 0, KAT_BENEFICIARY) != AUTH_A_DIGEST, "chain-bound");
    }

    /// The fixture enclave key's authorization opens a challenge at the fixed address,
    /// records the signed beneficiary and the submitter separately, and the six-word
    /// `challenges` getter decodes as documented.
    function test_rust_enclave_authorization_opens_challenge_at_fixed_settlement() public {
        DarkPerpSettlement d = _etchedSettlement();
        xvm.chainId(BASE_SEPOLIA);
        vm.warp(1_700_000_000);
        vm.roll(77);
        vm.deal(address(this), 1 ether);
        (uint8 v, bytes32 r, bytes32 sg) = _split(AUTH_A_SIG);
        assertEq(ecrecover(AUTH_A_DIGEST, v, r, sg), RUST_ENCLAVE, "vector recovers to the fixture enclave");

        xvm.recordLogs();
        d.challengeInclusion{value: 0.01 ether}(RUST_ORDER_HASH, 0, 1000, 0, KAT_BENEFICIARY, AUTH_A_SIG);
        CrossLayerVm.Log[] memory logs = xvm.getRecordedLogs();
        bool seen;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != KAT_SETTLEMENT) continue;
            // InclusionChallenged(bytes32 indexed,address indexed,address,uint256), from `cast keccak`
            assertEq(logs[i].topics[0], 0x16a25995582a5d2e093efeec773455d64ba9532b4523ad1036ccf5ed3c9add0d, "topic0");
            assertEq(logs[i].topics[1], RUST_ORDER_HASH, "order hash topic");
            assertEq(logs[i].topics[2], bytes32(uint256(uint160(KAT_BENEFICIARY))), "beneficiary topic");
            assertEq(keccak256(logs[i].data), keccak256(abi.encode(address(this), uint256(0))), "staker, batch");
            seen = true;
        }
        assertTrue(seen, "InclusionChallenged emitted");

        // Six ABI words: beneficiary, batchIdHint, openedBlock, openBatchCount, bond, open.
        (bool ok, bytes memory ret) =
            KAT_SETTLEMENT.staticcall(abi.encodeWithSelector(bytes4(0xc1e69b66), RUST_ORDER_HASH));
        assertTrue(ok, "getter");
        assertEq(ret.length, 192, "six words");
        (address ben, uint64 hint, uint256 openedBlock, uint256 openBatchCount, uint256 bond, bool open) =
            abi.decode(ret, (address, uint64, uint256, uint256, uint256, bool));
        assertEq(ben, KAT_BENEFICIARY, "beneficiary word");
        assertEq(uint256(hint), 0, "hint word");
        assertEq(openedBlock, 77, "opened block word");
        assertEq(openBatchCount, 0, "open batch count word");
        assertEq(bond, 0.01 ether, "stake word");
        assertTrue(open, "open word");
        assertEq(d.openChallengeCount(), 1, "open set");
        assertEq(d.openChallenges(0, 1)[0], RUST_ORDER_HASH, "open set member");
    }

    function test_fixed_authorization_is_bound_to_chain_settlement_and_beneficiary() public {
        DarkPerpSettlement d = _etchedSettlement();
        vm.warp(1_700_000_000);
        vm.deal(address(this), 1 ether);
        // Another chain id.
        xvm.chainId(BASE_SEPOLIA + 1);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        d.challengeInclusion{value: 0.01 ether}(RUST_ORDER_HASH, 0, 1000, 0, KAT_BENEFICIARY, AUTH_A_SIG);
        xvm.chainId(BASE_SEPOLIA);
        // Another beneficiary.
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        d.challengeInclusion{value: 0.01 ether}(RUST_ORDER_HASH, 0, 1000, 0, address(this), AUTH_A_SIG);
        // Another settlement with the same immutables (the un-etched copy).
        DarkPerpSettlement other = new DarkPerpSettlement(
            SettlementTestConfig.legacy(
                address(this),
                RUST_ENCLAVE,
                new MockClockVerifier(),
                bytes32(0),
                43_200,
                3_600,
                0.01 ether,
                3_600,
                address(this),
                300
            )
        );
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        other.challengeInclusion{value: 0.01 ether}(RUST_ORDER_HASH, 0, 1000, 0, KAT_BENEFICIARY, AUTH_A_SIG);
        // The exact tuple still opens.
        d.challengeInclusion{value: 0.01 ether}(RUST_ORDER_HASH, 0, 1000, 0, KAT_BENEFICIARY, AUTH_A_SIG);
        assertEq(d.openChallengeCount(), 1, "opened");
    }

    // --- deposit permit -----------------------------------------------------------------

    /// The gateway demo signer's permit verifies at the fixed vault on 84532 and the
    /// deposit lands with the independently computed chain tip.
    function test_permit_digest_kat_at_fixed_vault_and_deposit_lands() public {
        MockUSDC usdc = new MockUSDC();
        MockSettlementGate gate = new MockSettlementGate();
        CollateralVault template = new CollateralVault(address(gate), address(usdc), DEMO_GATEWAY_SIGNER);
        xvm.etch(KAT_VAULT, address(template).code);
        xvm.store(KAT_VAULT, bytes32(VAULT_GATEWAY_SIGNER_SLOT), bytes32(uint256(uint160(DEMO_GATEWAY_SIGNER))));
        CollateralVault v = CollateralVault(KAT_VAULT);
        assertEq(v.gatewaySigner(), DEMO_GATEWAY_SIGNER, "signer slot");
        gate.setVault(KAT_VAULT);
        xvm.chainId(BASE_SEPOLIA);

        assertEq(
            v.permitDigest(PERMIT_FROM, PERMIT_COMMIT, PERMIT_AMOUNT, PERMIT_VALID_UNTIL), PERMIT_DIGEST, "permit KAT"
        );
        assertEq(
            SettlementTestConfig.permitDigest(KAT_VAULT, PERMIT_FROM, PERMIT_COMMIT, PERMIT_AMOUNT, PERMIT_VALID_UNTIL),
            PERMIT_DIGEST,
            "helper digest"
        );
        (uint8 pv, bytes32 pr, bytes32 ps) = _split(PERMIT_SIG);
        assertEq(ecrecover(PERMIT_DIGEST, pv, pr, ps), DEMO_GATEWAY_SIGNER, "vector recovers to the gateway");

        usdc.mint(PERMIT_FROM, PERMIT_AMOUNT);
        vm.prank(PERMIT_FROM);
        usdc.approve(KAT_VAULT, PERMIT_AMOUNT);
        // The signature covers validUntil and the chain.
        vm.prank(PERMIT_FROM);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        v.deposit(PERMIT_AMOUNT, PERMIT_COMMIT, PERMIT_VALID_UNTIL + 1, PERMIT_SIG);
        xvm.chainId(BASE_SEPOLIA + 1);
        vm.prank(PERMIT_FROM);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        v.deposit(PERMIT_AMOUNT, PERMIT_COMMIT, PERMIT_VALID_UNTIL, PERMIT_SIG);
        xvm.chainId(BASE_SEPOLIA);

        vm.prank(PERMIT_FROM);
        v.deposit(PERMIT_AMOUNT, PERMIT_COMMIT, PERMIT_VALID_UNTIL, PERMIT_SIG);
        assertEq(uint256(v.depositCount()), 1, "one deposit");
        assertEq(v.depositChainTip(), PERMIT_DEPOSIT_TIP, "tip KAT");
        assertEq(v.depositTipAt(1), PERMIT_DEPOSIT_TIP, "prefix tip");
        assertTrue(v.usedOwnerCommit(PERMIT_COMMIT), "commit used");
        assertEq(usdc.balanceOf(KAT_VAULT), PERMIT_AMOUNT, "funds in the vault");
    }

    // --- ABI pins for off-chain callers -------------------------------------------------

    /// Selectors and event topics the gateway, tools and frontend hard-code, against
    /// `cast sig` / `cast keccak` of the canonical signatures. Public getters are reached
    /// through a typed zero address (no call is made).
    function test_selectors_and_topics_match_independent_vectors() public view {
        assertTrue(DarkPerpSettlement.settleBatch.selector == bytes4(0xf92fc4d4), "settleBatch");
        assertTrue(DarkPerpSettlement.challengeInclusion.selector == bytes4(0x7422b0ea), "challengeInclusion");
        assertTrue(DarkPerpSettlement.answerChallenge.selector == bytes4(0xa5f06b0e), "answerChallenge");
        assertTrue(DarkPerpSettlement.answerByRejection.selector == bytes4(0x48c01f1f), "answerByRejection");
        assertTrue(DarkPerpSettlement.answerChallenges.selector == bytes4(0x81913954), "answerChallenges");
        assertTrue(DarkPerpSettlement.slashUnanswered.selector == bytes4(0xb7bea4ba), "slashUnanswered");
        assertTrue(DarkPerpSettlement.releaseStaleChallenge.selector == bytes4(0x7674bee2), "releaseStaleChallenge");
        assertTrue(DarkPerpSettlement.openChallengeCount.selector == bytes4(0x6f443c06), "openChallengeCount");
        assertTrue(DarkPerpSettlement.openChallenges.selector == bytes4(0x555fa4f8), "openChallenges");
        assertTrue(DarkPerpSettlement.challengeAuthDigest.selector == bytes4(0x441859ad), "challengeAuthDigest");
        assertTrue(DarkPerpSettlement(address(0)).challenges.selector == bytes4(0xc1e69b66), "challenges");
        assertTrue(
            DarkPerpSettlement(address(0)).consumedDepositCount.selector == bytes4(0xbefd565d), "consumedDepositCount"
        );
        assertTrue(DarkPerpSettlement.depositGate.selector == bytes4(0x7404d348), "depositGate");
        assertTrue(DarkPerpSettlement.depositCapacity.selector == bytes4(0xf35ce643), "depositCapacity");
        assertTrue(DarkPerpSettlement.triggerCloseOnly.selector == bytes4(0xa6f5545a), "triggerCloseOnly");
        assertTrue(DarkPerpSettlement.enterCloseOnly.selector == bytes4(0xae0f2ffc), "enterCloseOnly");
        assertTrue(DarkPerpSettlement(address(0)).ABI_VERSION.selector == bytes4(0xf6b45cfd), "ABI_VERSION");
        assertTrue(CollateralVault.deposit.selector == bytes4(0xa1059e34), "deposit");
        assertTrue(CollateralVault.refundDeposit.selector == bytes4(0xb07e8ad3), "refundDeposit");
        assertTrue(CollateralVault.permitDigest.selector == bytes4(0x912733da), "permitDigest");
        assertTrue(CollateralVault.depositBlock.selector == bytes4(0x24680e53), "depositBlock");
        assertTrue(CollateralVault.refundableOutstanding.selector == bytes4(0x92fc1d19), "refundableOutstanding");
        assertTrue(ClockBoundVerifier.cancel.selector == bytes4(0x422e31bd), "cancel");
        assertTrue(ClockBoundVerifier(address(0)).cancelledReceipt.selector == bytes4(0x56a21054), "cancelledReceipt");
        assertTrue(ClockBoundVerifier(address(0)).anchorTimeoutMs.selector == bytes4(0x79902111), "anchorTimeoutMs");

        assertEq(
            DarkPerpSettlement.InclusionChallenged.selector,
            0x16a25995582a5d2e093efeec773455d64ba9532b4523ad1036ccf5ed3c9add0d,
            "InclusionChallenged"
        );
        assertEq(
            DarkPerpSettlement.SequencerSlashed.selector,
            0xc6dd54b9cdbc0cda7d9ccd0b3c9e52a02201dea770fa3d60de4645b82088f020,
            "SequencerSlashed"
        );
        assertEq(
            DarkPerpSettlement.ChallengeReleased.selector,
            0xb09980ff5485c8f5bd046c26c9882bca2e511046120072571e5e0b3f9cdd0a35,
            "ChallengeReleased"
        );
        assertEq(
            DarkPerpSettlement.CloseOnlyEntered.selector,
            0x39b3b40109fead2bcf41a503c62bde8b5486e20c4da2625b2192a2a02cfafda9,
            "CloseOnlyEntered"
        );
        assertEq(
            DarkPerpSettlement.BatchSettled.selector,
            0xf82e42f907bb0350a25eb9aebb7e72e66af212aaadb583992169340302079392,
            "BatchSettled"
        );
        assertEq(
            CollateralVault.DepositRefunded.selector,
            0xa80355a5c92c1a6019875d4ebea85e10c6d0b2412eee86bab0b577c1c78fcf72,
            "DepositRefunded"
        );
        assertEq(
            CollateralVault.Deposit.selector,
            0xdf3f00354434921901d8a49f26c4b0e4a907d497e57f2e9478e9ba4ea43eb0f9,
            "Deposit"
        );
        assertEq(
            ClockBoundVerifier.ClockCancelled.selector,
            0xfaa0971776597d114f0c99710538f5b1d23c25afc07fcd6c9b7d724f6d405815,
            "ClockCancelled"
        );
    }

    function _split(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 sg) {
        require(sig.length == 65, "sig length");
        assembly {
            r := mload(add(sig, 32))
            sg := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
