"""Every hard-coded copy of a clock identity pin agrees with the record it copies.

REVIEWED_GUEST copies live in the sp1-host binaries, the prover-service identity
test and the operator docs; PROOF_FIXTURE copies live in the real-proof Solidity
test, the fixture READMEs and the fixture's execution record. A record change that
leaves a copy behind fails here instead of in a later, slower gate. The gateway
drills read the on-disk format magics from the Rust sources.
"""
import functools
import gzip
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import tokenize
import unittest

import gateway_formats
import verify_clock_fixture as fixture
import verify_clock_proof as clock

ROOT = clock.target.ROOT
REVIEWED = clock.REVIEWED_GUEST
PROOF = clock.PROOF_FIXTURE


def source(relative):
    return (ROOT / relative).read_text()


def one(pattern, text, label):
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def hex64(text):
    """Every 64-hex-digit value in a text, lower case and without a 0x prefix."""
    return {value.lower() for value in re.findall(r"(?<![0-9A-Fa-fx])(?:0x)?([0-9A-Fa-f]{64})(?![0-9A-Fa-f])", text)}


def record_values(record):
    """Every 64-hex value a record holds (nested source and negative maps included)."""
    values = set()
    for value in record.values():
        if isinstance(value, dict):
            values |= record_values(value)
        elif isinstance(value, str):
            values |= hex64(value)
    return values


@functools.cache
def _claim_tool():
    # The repository's Solidity-compatible Keccak (original padding), covered by
    # scripts/claim's vectors; loaded by path so no second implementation exists.
    spec = importlib.util.spec_from_file_location("_claim_keccak", ROOT / "scripts/claim/claim_withdrawal.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def keccak256(data):
    return _claim_tool().keccak256(data)


def word(value):
    """One ABI word: an int, a 20-byte address or a 32-byte value."""
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    return bytes(32 - len(value)) + value


class ReviewedGuestCopies(unittest.TestCase):
    def test_sp1_host_reviewed_elf_pins(self):
        for relative in ("crates/sp1-host/src/bin/replay-funds.rs", "crates/sp1-host/src/bin/clock-proof.rs"):
            with self.subTest(file=relative):
                pinned = one(r'^const REVIEWED_ELF: &str\s*=\s*"([0-9a-f]{64})";', source(relative), "REVIEWED_ELF")
                self.assertEqual(pinned, REVIEWED["elf"])

    def test_clock_proof_takes_an_explicit_elf(self):
        text = source("crates/sp1-host/src/bin/clock-proof.rs")
        self.assertNotIn("include_elf!", text)
        self.assertIn('"--elf"', text)
        self.assertIn('"--no-prove"', text)
        # Execution only builds the execute-only client, never the CPU proving stack.
        self.assertEqual(text.count("ProverClient::builder().light().build()"), 1)
        self.assertEqual(text.count("ProverClient::builder().cpu().build()"), 1)

    def test_ci_builds_the_identity_binaries_and_describes_their_pins(self):
        ci = source(".github/workflows/ci.yml")
        # The prover crates job (with replay-funds) and the reviewed guest execution job.
        builds = re.findall(r"^\s*run: (cargo build --release --locked --manifest-path crates/sp1-host/Cargo\.toml .*)$",
                            ci, flags=re.MULTILINE)
        self.assertEqual(len(builds), 2)
        for build in builds:
            with self.subTest(build=build):
                self.assertIn("--bin vkey", build)
                self.assertIn("--bin clock-proof", build)
        self.assertEqual(sum("--bin replay-funds" in build for build in builds), 1)
        # The frozen Chainlink candidate hosts are no longer executed by a required job.
        self.assertFalse(any("replay-chainlink" in build for build in builds))
        comment = one(r"((?:^\s*#.*\n)+)\s*- name: Build optimized exact synthetic funds replay host", ci,
                      "release build comment")
        vkey = source("crates/sp1-host/src/bin/vkey.rs")
        # vkey enforces no pin (it keeps a build-script fallback); clock-proof does.
        self.assertIn("include_elf!", vkey)
        self.assertNotIn("REVIEWED_ELF", vkey)
        self.assertIn("enforces no pin", comment)
        self.assertNotRegex(comment, r"vkey and clock-proof take the reviewed ELF")
        self.assertIn("refuses", comment)

    def test_finish_clock_wrapper_setup_key(self):
        text = source("crates/sp1-host/src/bin/finish-clock-wrapper.rs")
        key = one(r'assert_eq!\(\s*vkey_hex,\s*"(0x[0-9a-f]{64})"\s*\)', text, "wrapper setup key")
        self.assertEqual(key, REVIEWED["vkey"])
        verifier = one(r'hex\(&groth\.groth16_vkey_hash\),\s*"([0-9a-f]{64})"', text, "wrapper verifier hash")
        self.assertEqual(verifier, clock.target.VERIFIER_HASH)

    def test_prover_service_identity_fixture(self):
        relative = "crates/prover-service/src/identity_tests.rs"
        text = source(relative)
        base = (ROOT / relative).parent
        for name, file in (("FIXTURE_ELF", "guest.elf"), ("FIXTURE_VKEY", "program-vkey.bin")):
            with self.subTest(constant=name):
                included = one(r'^const %s: &\[u8\]\s*=\s*include_bytes!\("([^"]+)"\);' % name, text, name)
                self.assertEqual((base / included).resolve(), (ROOT / REVIEWED["identity_dir"] / file).resolve())
        elf = one(r'sha256\(FIXTURE_ELF\),\s*"([0-9a-f]{64})"', text, "fixture ELF hash")
        self.assertEqual(elf, REVIEWED["elf"])
        key = one(r'assert_eq!\(\s*key,\s*"(0x[0-9a-f]{64})"\s*\)', text, "fixture setup key")
        self.assertEqual(key, REVIEWED["vkey"])
        size = (ROOT / REVIEWED["identity_dir"] / "guest.elf").stat().st_size
        for pattern in (r'FIXTURE_ELF\.len\(\),\s*([0-9_]+)\)', r'first\["elf_bytes"\],\s*([0-9_]+)\)'):
            with self.subTest(size=pattern):
                self.assertEqual(int(one(pattern, text, "fixture ELF size").replace("_", "")), size)

    def test_prover_service_program_domains(self):
        # The prover's /identity reports a witness domain only for a program its
        # table lists with it. Only REVIEWED_GUEST's ELF may be listed with the
        # admitted domain, and it must be unless it is listed as an earlier program.
        text = source("crates/prover-service/src/identity.rs")
        domain = one(r'^pub\(crate\) const WITNESS_DOMAIN: &str = "([A-Z0-9]+)";', text, "witness domain")
        block = re.search(r"PROGRAM_WITNESS_DOMAINS: &\[\(&str, &str\)\] = &\[(.*?)\n\];", text, re.S)
        self.assertIsNotNone(block, "program table")
        block = block.group(1)
        table = re.findall(r'\(\s*"([0-9a-f]{64})",\s*"([A-Z0-9]+)",?\s*\)', block)
        self.assertTrue(table, "the program table is parsed")
        self.assertEqual(len({sha for sha, _ in table}), len(table), "one entry per program")
        admitted = {sha for sha, listed in table if listed == domain}
        self.assertLessEqual(admitted, {REVIEWED["elf"]})
        if REVIEWED["elf"] not in {sha for sha, listed in table if listed != domain}:
            self.assertIn(REVIEWED["elf"], admitted, "the reviewed guest must be listed with " + domain)

    def test_reviewed_identity_directory(self):
        directory = ROOT / REVIEWED["identity_dir"]
        self.assertEqual(clock.target.sha256((directory / "guest.elf").read_bytes()), REVIEWED["elf"])
        self.assertEqual("0x" + (directory / "program-vkey.bin").read_bytes().hex(), REVIEWED["vkey"])


# The proof fixture's clock context and synthetic flow, as ClockBoundRealProof.t.sol
# sets them up (chain, constructor policy, registration, deposit and claim).
REAL_PROOF_CONTEXT = {"chain_id": 84532, "batch_id": 0, "phase": 0, "first_ms": 100_000, "last_ms": 100_700,
                      "timed_ops": 2, "anchored_at_ms": 101_000, "max_window_ms": 10_000, "clock_skew_ms": 2_000,
                      "amount": 1_000_000, "deposit_id": 0, "withdrawal_nonce": 1}
REAL_PROOF_CALLS = (
    "vm.chainId(84532);", "vm.warp(101);", "abi.encode(inner, uint64(10_000), uint64(2_000), uint64(3_600_000))",
    "clock.register(0, PREV, BASE, 100_000, 100_700, 2, 0)", "vm.startPrank(address(0));",
    "vault.deposit(1_000_000, OWNER_COMMIT, validUntil,", "new bytes32[](0)",
    "vault.claim(RECIPIENT, 1_000_000, 1, WITHDRAWALS, siblings);",
    "settlement.publicCommitment(PREV, MANIFEST, NEXT, bytes32(0), WITHDRAWALS, bytes32(0), DEPOSITS)",
    "settlement.settleBatch(PREV, MANIFEST, NEXT, bytes32(0), WITHDRAWALS, bytes32(0), DEPOSITS, 1, supplied);")
REAL_PROOF_CONSTANTS = {"PREV", "MANIFEST", "NEXT", "WITHDRAWALS", "DEPOSITS", "OWNER_COMMIT", "BASE", "RECEIPT",
                        "BOUND"}


class ProofFixtureCopies(unittest.TestCase):
    def test_keccak_known_answer(self):
        self.assertEqual(keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_real_proof_solidity_constants(self):
        text = source("contracts/integration/ClockBoundRealProof.t.sol")
        bound = one(r'bytes32 internal constant BOUND = (0x[0-9a-f]{64});', text, "BOUND")
        self.assertEqual(bound, PROOF["commitment"])
        key = one(r'require\(key == (0x[0-9a-f]{64}), "wrong guest key"\);', text, "guest key")
        self.assertEqual(key, PROOF["vkey"])
        # The previous root and base commitment are the proof witness's clock context.
        witness = (ROOT / PROOF["dir"] / "clock.witness.bin").read_bytes()
        for name in ("PREV", "BASE"):
            with self.subTest(constant=name):
                value = one(r'bytes32 internal constant %s = 0x([0-9a-f]{64});' % name, text, name)
                self.assertIn(bytes.fromhex(value), witness)

    def test_every_real_proof_constant_derives_the_proof_commitment(self):
        """KAT: recompute each derived constant with the contracts' formulas, ending at BOUND.

        BOUND is the committed proof's public value, so every constant that feeds it
        (all nine) is tied to PROOF_FIXTURE: a stale one fails here by name.
        """
        text = source("contracts/integration/ClockBoundRealProof.t.sol")
        c = {name: bytes.fromhex(value) for name, value in
             re.findall(r"^\s*bytes32 internal constant (\w+) = 0x([0-9a-f]{64});", text, flags=re.MULTILINE)}
        self.assertEqual(set(c), REAL_PROOF_CONSTANTS)
        a = {name: bytes.fromhex(value) for name, value in re.findall(
            r'address internal constant (\w+) = address\(bytes20\(hex"([0-9a-f]{40})"\)\);', text)}
        self.assertEqual(set(a), {"CLOCK", "SETTLEMENT", "RECIPIENT"})
        for call in REAL_PROOF_CALLS:
            with self.subTest(call=call):
                self.assertIn(call, text)
        # Every registration in the suite uses the proof's clock context.
        self.assertEqual(set(re.findall(r"clock\.register\(([^)]*)\)", text)), {"0, PREV, BASE, 100_000, 100_700, 2, 0"})
        settlement, vault, clock_src = (source("contracts/src/" + name) for name in
                                        ("DarkPerpSettlement.sol", "CollateralVault.sol", "ClockBoundVerifier.sol"))
        self.assertIn("uint8 internal constant DOMAIN_STATE_ROOT = 7;", settlement)
        self.assertIn('bytes32 public constant DOMAIN = keccak256("arcora:clock-bound-proof:v2");', clock_src)
        self.assertIn("bytes32 leaf = keccak256(abi.encodePacked(msg.sender, ownerCommit, amount, uint256(id)));",
                      vault)
        self.assertIn("bytes32 tip = keccak256(abi.encodePacked(depositChainTip, leaf));", vault)
        self.assertIn("bytes32 leaf = keccak256(abi.encodePacked(to, amount, nonce));", vault)
        self.assertIn("bytes32 bound = keccak256(abi.encode(DOMAIN, baseCommitment, a.receipt));", clock_src)
        x = REAL_PROOF_CONTEXT
        derived = {}
        # CollateralVault.claim with no siblings: the root is the single withdrawal leaf.
        derived["WITHDRAWALS"] = keccak256(a["RECIPIENT"] + word(x["amount"]) + word(x["withdrawal_nonce"]))
        # CollateralVault.deposit from the zero payer into an empty chain.
        leaf = keccak256(bytes(20) + c["OWNER_COMMIT"] + word(x["amount"]) + word(x["deposit_id"]))
        derived["DEPOSITS"] = keccak256(bytes(32) + leaf)
        # DarkPerpSettlement.publicCommitment (ordered and rejected roots are zero).
        derived["BASE"] = keccak256(bytes([7]) + c["PREV"] + c["MANIFEST"] + c["NEXT"] + bytes(32)
                                    + c["WITHDRAWALS"] + bytes(32) + c["DEPOSITS"])
        # ClockBoundVerifier.register receipt.
        domain = keccak256(b"arcora:clock-bound-proof:v2")
        derived["RECEIPT"] = keccak256(b"".join(word(v) for v in (
            domain, x["chain_id"], a["CLOCK"], a["SETTLEMENT"], x["batch_id"], c["PREV"], c["BASE"], x["phase"],
            x["first_ms"], x["last_ms"], x["timed_ops"], x["anchored_at_ms"], x["max_window_ms"],
            x["clock_skew_ms"])))
        # ClockBoundVerifier.verify bound commitment: the proof's public value.
        derived["BOUND"] = keccak256(domain + c["BASE"] + c["RECEIPT"])
        for name, value in derived.items():
            with self.subTest(constant=name):
                self.assertEqual("0x" + value.hex(), "0x" + c[name].hex())
        public_values = (ROOT / PROOF["dir"] / "public-values.bin").read_bytes()
        self.assertEqual("0x" + derived["BOUND"].hex(), PROOF["commitment"])
        self.assertEqual(derived["BOUND"], public_values)

    def test_proof_fixture_record_matches_its_directory(self):
        directory = ROOT / PROOF["dir"]
        files = clock.read_clock_artifacts(directory)
        sha = clock.target.sha256
        self.assertEqual(sha(files["guest.elf"]), PROOF["elf"])
        self.assertEqual("0x" + files["program-vkey.bin"].hex(), PROOF["vkey"])
        self.assertEqual(sha(files["clock.witness.bin"]), PROOF["witness_sha256"])
        self.assertEqual("0x" + files["public-values.bin"].hex(), PROOF["commitment"])
        self.assertEqual(sha(files["proof.bin"]), PROOF["proof_sha256"])
        evidence = json.loads(files["proof-evidence.json"])
        self.assertEqual(evidence["kind"], PROOF["kind"])
        self.assertEqual({n["name"]: n["witness_sha256"] for n in evidence["negatives"]}, PROOF["negatives"])
        calldata = (clock.target.CONTRACTS / fixture.CALLDATA).read_bytes()
        self.assertEqual(sha(calldata), PROOF["proof_sha256"])
        # The execution record committed beside the proof describes the same run.
        execution = json.loads((directory / "execution.json").read_text())
        self.assertEqual((execution["kind"], execution["elf_sha256"], execution["program_vkey"],
                          execution["witness_sha256"], execution["commitment"]),
                         (PROOF["kind"], PROOF["elf"], PROOF["vkey"], PROOF["witness_sha256"], PROOF["commitment"]))
        self.assertEqual({n["name"]: n["witness_sha256"] for n in execution["negatives"]}, PROOF["negatives"])
        self.assertEqual(execution["cycles"], evidence["cycles"])

    def test_reviewed_fixture_negatives_match_the_proof_negatives_by_name(self):
        # The reviewed fixture may add negatives; it never drops one the proof covers.
        self.assertLessEqual(set(PROOF["negatives"]), set(clock.REVIEWED_FIXTURE["negatives"]))

    def test_reviewed_fixture_record_matches_its_directory(self):
        # The committed clock-proof --no-prove record in identity_dir is the record
        # REVIEWED_FIXTURE copies, and its witness files are the recorded ones.
        reviewed = clock.REVIEWED_FIXTURE
        directory = ROOT / REVIEWED["identity_dir"]
        sha = clock.target.sha256
        execution = json.loads((directory / "execution.json").read_text())
        self.assertEqual((execution["elf_sha256"], execution["witness_sha256"], execution["commitment"]),
                         (REVIEWED["elf"], reviewed["witness_sha256"], reviewed["commitment"]))
        self.assertEqual((execution["proof_generated"], execution["setup_performed"]), (False, False))
        self.assertEqual(sha((directory / "clock.witness.bin").read_bytes()), reviewed["witness_sha256"])
        self.assertEqual({n["name"]: n["witness_sha256"] for n in execution["negatives"]}, reviewed["negatives"])
        self.assertEqual({c["name"]: {"witness_sha256": c["witness_sha256"], "commitment": c["commitment"]}
                          for c in execution["cases"]}, reviewed["cases"])
        for sub, expected in (("negatives", reviewed["negatives"]),
                              ("cases", {name: case["witness_sha256"] for name, case in reviewed["cases"].items()})):
            with self.subTest(directory=sub):
                files = {path.name: sha(path.read_bytes()) for path in (directory / sub).iterdir()}
                self.assertEqual(files, {name + ".witness.bin": digest for name, digest in expected.items()})

    def test_reviewed_fixture_equals_the_proof_fixture_while_the_guests_match(self):
        # While the proof's guest is the reviewed guest, the reviewed fixture's outputs
        # are the proof fixture's: every REVIEWED_FIXTURE value has a checked copy.
        if not clock.proof_matches_reviewed_guest():
            self.skipTest("the reviewed guest differs from the proof's guest")
        reviewed = clock.REVIEWED_FIXTURE
        self.assertEqual((reviewed["witness_sha256"], reviewed["commitment"], reviewed["negatives"]),
                         (PROOF["witness_sha256"], PROOF["commitment"], PROOF["negatives"]))
        self.assertEqual(reviewed["cases"], {})


# Prose copies of identity values, with the record each copies and the fields it
# must quote. Every 64-hex value in such a file is one of that record's values or
# one of the listed independent pins.
DOC_COPIES = {
    "docs/RELEASE_MANIFEST.md": (REVIEWED, ("elf", "vkey")),
    "docs/COLD_GUEST_REBUILD.md": (REVIEWED, ("elf",)),
    "contracts/integration/fixtures/clock-v2/README.md": (PROOF, ("elf", "commitment")),
    "contracts/integration/fixtures/clock-v2/verified-calldata/README.md": (PROOF, ("proof_sha256",)),
    "contracts/integration/fixtures/clock-v2-verified/README.md": (PROOF, ()),
    "contracts/integration/fixtures/clock-pkg3-reviewed/README.md": (REVIEWED, ("elf", "vkey")),
}


class DocumentCopies(unittest.TestCase):
    def independent_pins(self, relative):
        if relative == "docs/COLD_GUEST_REBUILD.md":
            recipe = source("scripts/local-verification/cold_rebuild_reviewed_guest.py")
            pins = {one(r"^%s = '([0-9a-f]{64})'$" % name, recipe, name) for name in ("TOOLCHAIN_SHA256", "RUSTC_SHA256")}
            # The git dependency's checked-out source tree, pinned with its commit.
            release = source("scripts/local-verification/check_sp1_release.py")
            return pins | {one(r'^    "source_tree_sha256": "([0-9a-f]{64})",$', release, "source_tree_sha256")}
        if relative == "contracts/integration/fixtures/clock-pkg3-reviewed/README.md":
            # The reviewed guest's fixture outputs, quoted beside its identity.
            return record_values(clock.REVIEWED_FIXTURE)
        if relative == "contracts/integration/fixtures/clock-v2/README.md":
            # The decompressed recursion witness that the committed proof wraps.
            witness = gzip.decompress((ROOT / "contracts/integration/fixtures/clock-v2/gnark-witness.json.gz").read_bytes())
            return {clock.target.sha256(witness)}
        return set()

    def test_document_copies_match_their_records(self):
        for relative, (record, fields) in DOC_COPIES.items():
            with self.subTest(file=relative):
                found = hex64(source(relative))
                for field in fields:
                    self.assertIn(record[field].removeprefix("0x"), found, field)
                self.assertLessEqual(found, record_values(record) | self.independent_pins(relative))

    def test_reviewed_fixture_readme_quotes_the_fixture(self):
        text = source("contracts/integration/fixtures/clock-pkg3-reviewed/README.md")
        found = hex64(text)
        for field in ("witness_sha256", "commitment"):
            with self.subTest(field=field):
                self.assertIn(clock.REVIEWED_FIXTURE[field].removeprefix("0x"), found)
        size = (ROOT / REVIEWED["identity_dir"] / "guest.elf").stat().st_size
        self.assertIn(str(size), text)
        for name in clock.REVIEWED_FIXTURE["cases"]:
            with self.subTest(case=name):
                self.assertIn(f"`{name}`", text)

    def test_cold_rebuild_doc_quotes_the_reviewed_elf_size(self):
        size = (ROOT / REVIEWED["identity_dir"] / "guest.elf").stat().st_size
        self.assertIn(str(size), source("docs/COLD_GUEST_REBUILD.md"))

    def test_value_scan_sees_prefixed_and_bare_values(self):
        text = "a 0x" + "Ab" * 32 + " b " + "cd" * 32 + " c " + "ef" * 33
        self.assertEqual(hex64(text), {"ab" * 32, "cd" * 32})


class AdmissionCapCopies(unittest.TestCase):
    """The gateway's admission bounds are the measurement gate's recommendation,
    and every document that quotes them quotes those values."""

    EVIDENCE = "docs/audits/2026-10-19-pkg3-measurement-gate/measurement.json"

    def bounds(self):
        text = source("crates/gateway/src/admission.rs")
        return {name: int(one(r"^pub\(crate\) const %s: u64 = ([0-9_]+);$" % name, text, name).replace("_", ""))
                for name in ("MAX_PROVABLE_HISTORY", "MAX_POSITIONS", "MAX_NOTES")}

    @staticmethod
    def soft(bound):
        return bound - bound // 5

    def test_gateway_bounds_equal_the_measured_recommendation(self):
        bounds = self.bounds()
        recommended = json.loads(source(self.EVIDENCE))["recommendation"]
        self.assertEqual(bounds, {"MAX_PROVABLE_HISTORY": recommended["max_provable_history"],
                                  "MAX_POSITIONS": recommended["max_positions"],
                                  "MAX_NOTES": recommended["max_notes"]})
        self.assertEqual(recommended["soft_cap_history"], self.soft(bounds["MAX_PROVABLE_HISTORY"]))
        self.assertTrue(recommended["adopt_keccak_precompile"])
        self.assertNotIn("PROVISIONAL", source("crates/gateway/src/admission.rs"))

    def test_documents_quote_the_gateway_bounds(self):
        bounds = self.bounds()
        hard = [bounds[name] for name in ("MAX_PROVABLE_HISTORY", "MAX_POSITIONS", "MAX_NOTES")]
        every = hard + [self.soft(value) for value in hard]
        quoted = {"docs/API.md": every, "docs/ECONOMIC_SECURITY.md": every,
                  "docs/public-site/api.html": every, "frontend/public/docs/api.html": every,
                  "docs/REDEPLOY-CC-RUNBOOK.md": hard,
                  "docs/audits/2026-10-19-pkg3-measurement-gate/README.md":
                      hard + [self.soft(bounds["MAX_PROVABLE_HISTORY"])]}
        for relative, values in quoted.items():
            text = source(relative)
            with self.subTest(file=relative):
                for value in values:
                    self.assertIn(f"{value:,}", text)
                self.assertNotIn("provisional until measured", text.lower())


class RecordShapes(unittest.TestCase):
    def test_records_have_their_fields(self):
        self.assertEqual(set(REVIEWED), {"elf", "vkey", "sources", "identity_dir"})
        self.assertEqual(set(clock.REVIEWED_FIXTURE), {"witness_sha256", "commitment", "negatives", "cases"})
        self.assertEqual(set(PROOF), {"dir", "kind", "elf", "vkey", "witness_sha256", "commitment",
                                      "proof_sha256", "negatives"})

    def test_historical_sources_cover_the_reviewed_paths(self):
        self.assertEqual(set(clock.HISTORICAL_V2_GUEST_SOURCES), set(REVIEWED["sources"]))
        self.assertEqual(len(REVIEWED["sources"]), 21)

    def test_historical_sources_equal_the_published_record(self):
        # Anchored to the source pins published with the 2026-10-11 preservation
        # record, so the frozen copy cannot drift once REVIEWED_GUEST moves on.
        published = json.loads(source(
            "docs/audits/2026-10-11-chainlink-native-contract-bridge/preservation-publication.json"))
        (pins,) = [entry for entry in published["source_pins"] if entry["name"] == "reviewed_v2"]
        self.assertEqual(pins["pin_count"], 21)
        self.assertEqual({entry["path"]: entry["expected_sha256"] for entry in pins["entries"]},
                         dict(clock.HISTORICAL_V2_GUEST_SOURCES))

    def test_old_single_identity_aliases_are_gone(self):
        names = {"EXPECTED_ELF", "EXPECTED_VKEY", "EXPECTED_WITNESS", "EXPECTED_COMMITMENT", "EXPECTED_GUEST_SOURCES"}
        for name in names:
            self.assertFalse(hasattr(clock, name), name)
        # Code references only: a recorded output label may still quote an old name.
        users = []
        for path in sorted((ROOT / "scripts/local-verification").glob("*.py")):
            tokens = tokenize.generate_tokens(io.StringIO(path.read_text()).readline)
            if any(token.type == tokenize.NAME and token.string in names for token in tokens):
                users.append(path.name)
        self.assertEqual(users, [])


class GatewayFormats(unittest.TestCase):
    def test_magics_are_parsed_from_the_rust_definitions(self):
        self.assertEqual(len(gateway_formats.snapshot_magic()), 8)
        self.assertTrue(gateway_formats.snapshot_magic().startswith(b"DPSNAP"))
        self.assertTrue(gateway_formats.journal_magic().startswith(b"DPRBJL"))
        self.assertTrue(gateway_formats.candidate_journal_magic().startswith(b"DPRBJL"))
        self.assertNotEqual(gateway_formats.journal_magic(), gateway_formats.candidate_journal_magic())
        snapshot = source(gateway_formats.SNAPSHOT_SOURCE)
        literal = gateway_formats.snapshot_magic().decode().replace("\0", "\\0")
        self.assertIn('const MAGIC: &[u8; 8] = b"%s";' % literal, snapshot)

    def test_drills_do_not_hard_code_a_format_magic(self):
        for name in ("gateway_ack_crash_drill.py", "gateway_restore_drill.py"):
            with self.subTest(drill=name):
                text = source("scripts/local-verification/" + name)
                self.assertNotRegex(text, r"b['\"]DP(?:SNAP|RBJL)")
                self.assertIn("gateway_formats.snapshot_magic()", text)

    def test_parser_refuses_ambiguous_or_malformed_definitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / gateway_formats.SNAPSHOT_SOURCE
            path.parent.mkdir(parents=True)
            cases = {
                'const MAGIC: &[u8; 8] = b"DPSNAP9\\0";\n': b"DPSNAP9\0",
                'pub(crate) const MAGIC: &[u8; 8] = b"AB\\x01\\x02\\n\\t\\\\\\"";\n': b'AB\x01\x02\n\t\\"',
            }
            for text, expected in cases.items():
                with self.subTest(text=text):
                    path.write_text("// const MAGIC: &[u8; 8] = b\"COMMENT\\0\";\n" + text)
                    self.assertEqual(gateway_formats.snapshot_magic(root), expected)
            for text in ('const MAGIC: &[u8; 8] = b"DPSNAP9\\0";\nconst MAGIC: &[u8; 8] = b"DPSNAP8\\0";\n',
                         'const MAGIC: &[u8; 7] = b"DPSNAP9";\n', 'const MAGIC: &[u8; 8] = b"DPSNAP\\0";\n',
                         'const MAGIC: &[u8; 8] = b"DPSNAP9\\q";\n', 'const OTHER: &[u8; 8] = b"DPSNAP9\\0";\n'):
                with self.subTest(text=text), self.assertRaises(ValueError):
                    path.write_text(text)
                    gateway_formats.snapshot_magic(root)


if __name__ == "__main__":
    unittest.main()
