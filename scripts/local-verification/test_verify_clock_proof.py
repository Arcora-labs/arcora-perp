import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import verify_clock_fixture as fixture
import verify_clock_proof as clock

# Distinct, well-formed values standing in for a changed reviewed guest. With
# these patched in, any path that reads REVIEWED where it must read PROOF_FIXTURE
# produces a value that differs from the committed proof.
DUMMY_GUEST = {"elf": "cd" * 32, "vkey": "0x" + "ab" * 32}
DUMMY_FIXTURE = {"witness_sha256": "ef" * 32, "commitment": "0x" + "12" * 32}
SUITES = {"SP1RealVerifierGuardTest": 8, "SP1RealProofTest": 10, "ClockBoundRealProofTest": 6}
# The evidence keys and scope text each gate wrote before the identity split. The
# split only adds keys next to these; a rename belongs to a change that intends it.
PROOF_REPORT_KEYS = {
    "status", "kind", "local_evm_only", "mock_proof_used", "production_deployed", "full_token_lifecycle",
    "clock_adapter_full_lifecycle", "clock_adapter_synthetic_settlement_verified",
    "synthetic_vault_claim_verified", "mock_token_used", "fixture_address_constructors",
    "synthetic_zero_payer_impersonated", "application_proof_accepted", "scope", "guest_elf_sha256",
    "program_vkey", "public_commitment", "tests", "input_artifacts", "runner_sha256", "guest_sources_sha256",
    "source_sha256", "compiled_contracts", "vendor_upstreams"}
PROOF_REPORT_SCOPE = ("Real clock-v2 proof through SP1 verifier, clock adapter, actual settlement and vault; "
                      "fixed synthetic addresses and a mock token, not live payer provenance or full "
                      "order/HTTP/production lifecycle.")
FIXTURE_REPORT_KEYS = {
    "status", "tests", "local_evm_only", "real_cryptographic_proof_verified", "mock_proof_used",
    "mock_token_used", "synthetic_zero_payer", "fixed_constructor_addresses", "production_deployed",
    "full_production_lifecycle", "sdk_verification_claimed", "proof_sha256", "guest_elf_sha256",
    "program_vkey", "public_commitment", "guest_source_sha256", "scope"}
FIXTURE_REPORT_SCOPE = ("Actual SP1 verifier, clock adapter, settlement and synthetic vault withdrawal; "
                        "not full HTTP/order/production lifecycle.")
# The guest inputs the reviewed guest changed since the clock-v2 guest: the guest
# entry point, its manifest and lockfile (the Keccak precompile patch), and twelve
# perp-core sources. The root and perp-core manifests, hash, market, note and
# oracle are unchanged.
CHANGED_SINCE_CLOCK_V2 = {
    "crates/sp1-guest/src/main.rs", "crates/sp1-guest/Cargo.toml", "crates/sp1-guest/Cargo.lock",
    *("crates/perp-core/src/" + name + ".rs" for name in (
        "clock", "commitment", "engine", "error", "fixed", "funding", "lib", "merkle", "nullifier", "order",
        "position", "state")),
}


def proof_identity_as_reviewed():
    """Patch REVIEWED_GUEST and REVIEWED_FIXTURE to the committed proof's own identity.

    The committed proof is of the earlier clock-v2 guest, so with the committed
    records proof_status() is PENDING_REPROOF. Inside this patch the records name
    that proof's guest and fixture, as they will once a proof of the reviewed
    fixture is committed, so the PROVEN path is exercised on real proof files.
    """
    stack = contextlib.ExitStack()
    stack.enter_context(patch.dict(clock.REVIEWED_GUEST, {"elf": clock.PROOF_FIXTURE["elf"],
                                                          "vkey": clock.PROOF_FIXTURE["vkey"]}))
    stack.enter_context(patch.dict(clock.REVIEWED_FIXTURE, {"witness_sha256": clock.PROOF_FIXTURE["witness_sha256"],
                                                            "commitment": clock.PROOF_FIXTURE["commitment"]}))
    return stack


def forge_stub(calls):
    """Record each forge invocation and answer as a passing real-proof run would."""
    def run(command, output, label, env):
        calls.append({"command": command, "label": label, "env": dict(env)})
        if label != "real-target-tests":
            return ""
        return json.dumps({f"integration/X.t.sol:{name}": {"test_results": {
            f"test_{i}": {"status": "Success"} for i in range(count)}} for name, count in SUITES.items()})
    return run


def compiled_stub(path):
    return {"compiler": "0.8.20+stub" if "sp1-upstream" in str(path) else "0.8.24+stub"}


class ClockProofArtifactGuards(unittest.TestCase):
    def test_checked_out_guest_source_matches_reviewed_pin(self):
        self.assertEqual(clock.verify_guest_source(), clock.REVIEWED_GUEST["sources"])

    def test_changed_guest_cannot_reuse_a_passing_old_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = clock.target.ROOT
            for name in clock.REVIEWED_GUEST["sources"]:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((original / name).read_bytes())
            with patch.object(clock.target, "ROOT", root):
                clock.verify_guest_source()
                file = root / "crates/sp1-guest/src/main.rs"
                file.write_bytes(file.read_bytes() + b"\n// changed guest input\n")
                with self.assertRaisesRegex(ValueError, "guest source changed"):
                    clock.verify_guest_source()
        # A rebuilt guest is a new REVIEWED identity; the committed proof is not its proof.
        self.assertFalse(clock.proof_matches_reviewed_guest())
        self.assertEqual(clock.proof_status(), clock.PENDING_REPROOF)
        with proof_identity_as_reviewed():
            self.assertEqual(clock.proof_status(), clock.PROVEN)
        with patch.dict(clock.REVIEWED_GUEST, DUMMY_GUEST):
            self.assertEqual(clock.proof_status(), clock.PENDING_REPROOF)
            self.assertFalse(clock.proof_matches_reviewed_guest())

    def test_missing_success_record_is_not_an_execution_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing"):
                clock.load_clock_proof(Path(directory))

    def test_artifact_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_text("{}")
            (root / "proof-evidence.json").symlink_to(root / "source")
            with self.assertRaisesRegex(ValueError, "nonregular"):
                clock.load_clock_proof(root)

    def test_unverified_or_wrong_version_evidence_is_refused(self):
        cases = [
            ({"kind": "ordinary-local-groth16-proof"}, "clock-v2"),
            ({"kind": "clock-v2-native-guest", "sdk_version": "6.0.0"}, "wrong SP1"),
            ({"kind": "clock-v2-native-guest", "sdk_version": "6.1.0", "proof_generated": False}, "incomplete"),
            ({"kind": "clock-v2-native-guest", "sdk_version": "6.1.0", "proof_generated": True,
              "local_sdk_verified": False}, "incomplete"),
        ]
        for record, error in cases:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ["clock.witness.bin", "guest.elf", "program-vkey.bin", "proof.bin",
                             "public-values.bin", "proof.sdk.json"]:
                    (root / name).write_bytes(b"not a real proof")
                (root / "proof-evidence.json").write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, error):
                    clock.load_clock_proof(root)

    def test_arbitrary_guest_cannot_nominate_its_own_vkey(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["clock.witness.bin", "guest.elf", "program-vkey.bin", "proof.bin",
                         "public-values.bin", "proof.sdk.json"]:
                (root / name).write_bytes(b"\x7fELFfake")
            (root / "proof-evidence.json").write_text(json.dumps({
                "kind": "clock-v2-native-guest", "sdk_version": "6.1.0",
                "proof_generated": True, "local_sdk_verified": True, "native_guest_equal": True,
                "elf_sha256": "attacker-selected-hash", "program_vkey": "attacker-selected-key",
            }))
            with self.assertRaisesRegex(ValueError, "wrong rebuilt clock guest"):
                clock.load_clock_proof(root)


class ProofFixtureAndStatus(unittest.TestCase):
    def copy_fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(clock.target.ROOT / clock.PROOF_FIXTURE["dir"], root / clock.PROOF_FIXTURE["dir"])
        return root

    def test_proof_fixture_record_is_self_consistent(self):
        files, env = clock.load_clock_proof(clock.target.ROOT / clock.PROOF_FIXTURE["dir"])
        self.assertEqual(clock.target.sha256(files["proof.bin"]), clock.PROOF_FIXTURE["proof_sha256"])
        self.assertEqual(env, {"ARCORA_REAL_PROGRAM_VKEY": clock.PROOF_FIXTURE["vkey"],
                               "ARCORA_REAL_PUBLIC_COMMITMENT": clock.PROOF_FIXTURE["commitment"],
                               "ARCORA_REAL_PROOF": "0x" + files["proof.bin"].hex()})
        evidence = json.loads(files["proof-evidence.json"])
        self.assertEqual({n["name"]: n["witness_sha256"] for n in evidence["negatives"]},
                         clock.PROOF_FIXTURE["negatives"])
        self.assertEqual(evidence["proof_sha256"], clock.PROOF_FIXTURE["proof_sha256"])

    def test_status_is_proven_only_for_the_reviewed_guest_and_fixture(self):
        # The committed proof is of the earlier clock-v2 guest, not of the reviewed one.
        self.assertFalse(clock.proof_matches_reviewed_guest())
        self.assertEqual(clock.proof_status(), clock.PENDING_REPROOF)
        for name in ("elf", "vkey"):
            self.assertNotEqual(clock.REVIEWED_GUEST[name], clock.PROOF_FIXTURE[name], name)
        for name in ("witness_sha256", "commitment"):
            self.assertNotEqual(clock.REVIEWED_FIXTURE[name], clock.PROOF_FIXTURE[name], name)
        # With records naming the proof's own guest and fixture the files are PROVEN,
        # and any one reviewed value that differs from the proof's makes them pending.
        with proof_identity_as_reviewed():
            self.assertTrue(clock.proof_matches_reviewed_guest())
            self.assertEqual(clock.proof_status(), clock.PROVEN)
            for record, values in ((clock.REVIEWED_GUEST, {"elf": DUMMY_GUEST["elf"]}),
                                   (clock.REVIEWED_GUEST, {"vkey": DUMMY_GUEST["vkey"]}),
                                   (clock.REVIEWED_FIXTURE, {"witness_sha256": DUMMY_FIXTURE["witness_sha256"]}),
                                   (clock.REVIEWED_FIXTURE, {"commitment": DUMMY_FIXTURE["commitment"]})):
                with self.subTest(values=values), patch.dict(record, values):
                    self.assertEqual(clock.proof_status(), clock.PENDING_REPROOF)

    def test_editing_the_proof_record_without_a_new_proof_stays_pending(self):
        # Pointing PROOF_FIXTURE's dict at a new reviewed guest does not make the
        # old proof files on disk a proof of that guest.
        with patch.dict(clock.REVIEWED_GUEST, DUMMY_GUEST), patch.dict(clock.REVIEWED_FIXTURE, DUMMY_FIXTURE), \
                patch.dict(clock.PROOF_FIXTURE, {**DUMMY_GUEST, **DUMMY_FIXTURE}):
            self.assertTrue(clock.proof_matches_reviewed_guest())
            self.assertEqual(clock.proof_status(), clock.PENDING_REPROOF)

    def test_status_reads_the_files_on_disk(self):
        root = self.copy_fixture()
        self.assertEqual(clock.proof_status(root), clock.PENDING_REPROOF)
        self.enterContext(proof_identity_as_reviewed())
        self.assertEqual(clock.proof_status(root), clock.PROVEN)
        directory = root / clock.PROOF_FIXTURE["dir"]
        evidence = json.loads((directory / "proof-evidence.json").read_text())
        mutations = {
            "proof.bin": lambda d: (d / "proof.bin").write_bytes((d / "proof.bin").read_bytes()[:-1] + b"\x00"),
            "guest.elf": lambda d: (d / "guest.elf").write_bytes((d / "guest.elf").read_bytes() + b"\x00"),
            "public-values.bin": lambda d: (d / "public-values.bin").write_bytes(bytes(32)),
            "missing": lambda d: (d / "program-vkey.bin").unlink(),
            "kind": lambda d: (d / "proof-evidence.json").write_text(json.dumps({**evidence, "kind": "other"})),
            "sdk": lambda d: (d / "proof-evidence.json").write_text(json.dumps({**evidence, "sdk_version": "6.0.0"})),
            "unverified": lambda d: (d / "proof-evidence.json").write_text(json.dumps(
                {**evidence, "rust_sp1_verifier_verified": False})),
            "recorded-elf": lambda d: (d / "proof-evidence.json").write_text(json.dumps(
                {**evidence, "elf_sha256": "00" * 32})),
            "malformed": lambda d: (d / "proof-evidence.json").write_text("{"),
        }
        mutations.update(self.evidence_mutations(evidence))
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                root = self.copy_fixture()
                mutate(root / clock.PROOF_FIXTURE["dir"])
                self.assertEqual(clock.proof_status(root), clock.PENDING_REPROOF)

    @staticmethod
    def evidence_mutations(evidence):
        def write(change):
            return lambda d: (d / "proof-evidence.json").write_text(json.dumps(change(dict(evidence))))

        def negatives(change):
            return write(lambda e: {**e, "negatives": [change(dict(n)) for n in e["negatives"]]})

        return {
            "negatives-missing": write(lambda e: {k: v for k, v in e.items() if k != "negatives"}),
            "negatives-empty": write(lambda e: {**e, "negatives": []}),
            "negatives-dropped": write(lambda e: {**e, "negatives": e["negatives"][1:]}),
            "negatives-accepted": negatives(lambda n: {**n, "guest_exit": 0, "public_bytes": 32}),
            "negatives-witness": negatives(lambda n: {**n, "witness_sha256": "00" * 32}),
            "negatives-not-records": write(lambda e: {**e, "negatives": [n["name"] for n in e["negatives"]]}),
            "negatives-unhashable-name": negatives(lambda n: {**n, "name": [n["name"]]}),
            "evidence-not-an-object": write(lambda e: [e]),
        }

    def test_status_and_the_proof_validator_refuse_the_same_evidence(self):
        # proof_status is built on load_clock_proof: evidence that verify_clock_proof
        # refuses is never PROVEN, and the refusal is a clean ValueError, not a crash.
        evidence = json.loads((clock.target.ROOT / clock.PROOF_FIXTURE["dir"] / "proof-evidence.json").read_text())
        for name, mutate in self.evidence_mutations(evidence).items():
            with self.subTest(mutation=name):
                root = self.copy_fixture()
                directory = root / clock.PROOF_FIXTURE["dir"]
                mutate(directory)
                with self.assertRaises(ValueError):
                    clock.load_clock_proof(directory)
                self.assertEqual(clock.proof_status(root), clock.PENDING_REPROOF)

    def rewrap(self, root):
        """A different, well-shaped proof of the same fixture (as a re-wrap of the guest yields)."""
        path = root / clock.PROOF_FIXTURE["dir"] / "proof.bin"
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        return path.read_bytes()

    def test_artifact_proof_bytes_are_not_pinned_to_the_committed_proof(self):
        # The artifact's proof bytes reach forge with PROOF_FIXTURE's key and commitment;
        # forge, not a byte pin, decides whether they verify.
        root = self.copy_fixture()
        proof = self.rewrap(root)
        self.assertNotEqual(clock.target.sha256(proof), clock.PROOF_FIXTURE["proof_sha256"])
        files, env = clock.load_clock_proof(root / clock.PROOF_FIXTURE["dir"])
        self.assertEqual(files["proof.bin"], proof)
        self.assertEqual(env, {"ARCORA_REAL_PROGRAM_VKEY": clock.PROOF_FIXTURE["vkey"],
                               "ARCORA_REAL_PUBLIC_COMMITMENT": clock.PROOF_FIXTURE["commitment"],
                               "ARCORA_REAL_PROOF": "0x" + proof.hex()})
        # It is not the committed proof, so the status stays pending.
        self.assertEqual(clock.proof_status(root), clock.PENDING_REPROOF)
        # Shape and verifier selector are still required.
        for name, data in (("selector", b"\x00" * 4 + proof[4:]), ("length", proof[:-1])):
            with self.subTest(refused=name):
                (root / clock.PROOF_FIXTURE["dir"] / "proof.bin").write_bytes(data)
                with self.assertRaisesRegex(ValueError, "Groth16 shape/selector"):
                    clock.load_clock_proof(root / clock.PROOF_FIXTURE["dir"])
                with self.assertRaisesRegex(ValueError, "Groth16 shape/selector"):
                    clock.forge_environment(data)

    def test_historical_sources_are_a_frozen_provenance_copy(self):
        historical = dict(clock.HISTORICAL_V2_GUEST_SOURCES)
        reviewed = clock.REVIEWED_GUEST["sources"]
        self.assertEqual(len(historical), 21)
        with self.assertRaises(TypeError):
            clock.HISTORICAL_V2_GUEST_SOURCES["Cargo.toml"] = "00" * 32
        # The frozen copy is the source set the committed clock-v2 proof was verified
        # against, as its evidence recorded it.
        evidence = json.loads((clock.target.ROOT / "docs/audits/2026-10-09-remaining-work/real-clock-proof/"
                               "verification.json").read_text())
        self.assertEqual(evidence["guest_sources_sha256"], historical)
        # The reviewed guest pins the same 21 inputs and differs exactly where they changed.
        self.assertEqual(set(reviewed), set(historical))
        changed = {name for name in reviewed if reviewed[name] != historical[name]}
        self.assertEqual(changed, CHANGED_SINCE_CLOCK_V2)
        # The checkout no longer matches the frozen copy, so it never passes the gate.
        with patch.dict(clock.REVIEWED_GUEST, {"sources": historical}):
            with self.assertRaisesRegex(ValueError, "guest source changed"):
                clock.verify_guest_source()
        # The checkout gate follows REVIEWED_GUEST, never the historical copy.
        changed = dict(clock.REVIEWED_GUEST["sources"], **{"Cargo.toml": "00" * 32})
        with patch.dict(clock.REVIEWED_GUEST, {"sources": changed}):
            with self.assertRaisesRegex(ValueError, "guest source changed"):
                clock.verify_guest_source()


class ForgeInputsComeFromProofFixture(unittest.TestCase):
    """With REVIEWED patched to dummy values, both gates still verify the committed proof."""

    def run_main(self, module, argv):
        calls = []
        output = Path(tempfile.mkdtemp()) / "out"
        self.addCleanup(shutil.rmtree, output.parent)
        with patch.dict(clock.REVIEWED_GUEST, DUMMY_GUEST), patch.dict(clock.REVIEWED_FIXTURE, DUMMY_FIXTURE), \
                patch.object(clock.target, "run", forge_stub(calls)), \
                patch.object(clock.target, "compiled_identity", compiled_stub), \
                patch.object(sys, "argv", [module.__file__, *argv, "--output-dir", str(output)]), \
                contextlib.redirect_stdout(io.StringIO()):
            module.main()
        return calls, json.loads((output / "verification.json").read_text())

    def assert_proof_fixture_inputs(self, calls, report):
        self.assertEqual([call["label"] for call in calls], ["upstream-build", "real-target-tests"])
        proof = (clock.target.ROOT / clock.PROOF_FIXTURE["dir"] / "proof.bin").read_bytes()
        for call in calls:
            env = call["env"]
            self.assertEqual(env["ARCORA_REAL_PROGRAM_VKEY"], clock.PROOF_FIXTURE["vkey"])
            self.assertEqual(env["ARCORA_REAL_PUBLIC_COMMITMENT"], clock.PROOF_FIXTURE["commitment"])
            self.assertEqual(env["ARCORA_REAL_PROOF"], "0x" + proof.hex())
            self.assertNotIn(DUMMY_GUEST["vkey"], json.dumps(env))
        self.assertEqual(report["tests"], SUITES)
        self.assertEqual((report["guest_elf_sha256"], report["program_vkey"], report["public_commitment"]),
                         (clock.PROOF_FIXTURE["elf"], clock.PROOF_FIXTURE["vkey"], clock.PROOF_FIXTURE["commitment"]))
        self.assertEqual(report["proof_fixture"]["proof_sha256"], clock.PROOF_FIXTURE["proof_sha256"])
        self.assertEqual(report["proof_fixture"]["program_vkey"], clock.PROOF_FIXTURE["vkey"])
        self.assertEqual(report["reviewed_guest"]["guest_elf_sha256"], DUMMY_GUEST["elf"])
        self.assertEqual(report["reviewed_guest"]["program_vkey"], DUMMY_GUEST["vkey"])
        self.assertIs(report["proof_matches_reviewed_guest"], False)
        self.assertEqual(report["real_proof_status"], clock.PENDING_REPROOF)

    def test_verify_clock_proof(self):
        calls, report = self.run_main(clock, ["--artifact-dir", str(clock.target.ROOT / clock.PROOF_FIXTURE["dir"])])
        self.assert_proof_fixture_inputs(calls, report)
        self.assertEqual(report["reviewed_guest_sources_sha256"], clock.REVIEWED_GUEST["sources"])

    def test_verify_clock_fixture(self):
        calls, report = self.run_main(fixture, [])
        self.assert_proof_fixture_inputs(calls, report)
        self.assertEqual(report["proof_sha256"], clock.PROOF_FIXTURE["proof_sha256"])

    def test_verify_clock_proof_passes_a_rewrapped_artifact_proof_to_forge(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory)
        artifact = directory / "artifact"
        shutil.copytree(clock.target.ROOT / clock.PROOF_FIXTURE["dir"], artifact)
        proof = (artifact / "proof.bin").read_bytes()
        proof = proof[:-1] + bytes([proof[-1] ^ 1])
        (artifact / "proof.bin").write_bytes(proof)
        calls, report = self.run_main(clock, ["--artifact-dir", str(artifact)])
        for call in calls:
            self.assertEqual(call["env"]["ARCORA_REAL_PROOF"], "0x" + proof.hex())
            self.assertEqual(call["env"]["ARCORA_REAL_PROGRAM_VKEY"], clock.PROOF_FIXTURE["vkey"])
            self.assertEqual(call["env"]["ARCORA_REAL_PUBLIC_COMMITMENT"], clock.PROOF_FIXTURE["commitment"])
        self.assertEqual(report["input_artifacts"]["proof.bin"]["sha256"], clock.target.sha256(proof))

    def test_verify_clock_fixture_still_pins_the_committed_calldata(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory)
        calldata = directory / fixture.CALLDATA
        calldata.parent.mkdir(parents=True)
        proof = (clock.target.CONTRACTS / fixture.CALLDATA).read_bytes()
        calldata.write_bytes(proof[:-1] + bytes([proof[-1] ^ 1]))
        calls = []
        with patch.object(clock.target, "CONTRACTS", directory), patch.object(clock.target, "run", forge_stub(calls)), \
                patch.object(sys, "argv", ["verify_clock_fixture.py", "--output-dir", str(directory / "out")]):
            with self.assertRaisesRegex(ValueError, "pinned proof changed"):
                fixture.main()
        self.assertEqual(calls, [])

    def test_existing_evidence_keys_and_scope_are_kept(self):
        for module, argv, keys, scope, sources in (
                (clock, ["--artifact-dir", str(clock.target.ROOT / clock.PROOF_FIXTURE["dir"])],
                 PROOF_REPORT_KEYS, PROOF_REPORT_SCOPE, "guest_sources_sha256"),
                (fixture, [], FIXTURE_REPORT_KEYS, FIXTURE_REPORT_SCOPE, "guest_source_sha256")):
            with self.subTest(gate=module.__name__):
                _, report = self.run_main(module, argv)
                self.assertLessEqual(keys, set(report))
                self.assertEqual(report["scope"], scope)
                self.assertEqual(report["identity_scope"], clock.IDENTITY_SCOPE)
                # The source pins the checkout was checked against, under both names.
                self.assertEqual(report[sources], clock.REVIEWED_GUEST["sources"])
                self.assertEqual(report["reviewed_" + sources], report[sources])

    def fixture_report(self):
        calls = []
        output = Path(tempfile.mkdtemp()) / "out"
        self.addCleanup(shutil.rmtree, output.parent)
        with patch.object(clock.target, "run", forge_stub(calls)), \
                patch.object(sys, "argv", ["verify_clock_fixture.py", "--output-dir", str(output)]), \
                contextlib.redirect_stdout(io.StringIO()):
            fixture.main()
        return json.loads((output / "verification.json").read_text())

    def test_committed_records_attest_a_proof_of_another_guest(self):
        # The gate verifies the committed proof and says it is not the reviewed guest's.
        report = self.fixture_report()
        self.assertIs(report["proof_matches_reviewed_guest"], False)
        self.assertEqual(report["real_proof_status"], clock.PENDING_REPROOF)
        self.assertEqual(report["reviewed_guest"]["guest_elf_sha256"], clock.REVIEWED_GUEST["elf"])
        self.assertEqual(report["proof_fixture"]["guest_elf_sha256"], clock.PROOF_FIXTURE["elf"])

    def test_matching_records_attest_a_matching_proof(self):
        with proof_identity_as_reviewed():
            report = self.fixture_report()
        self.assertIs(report["proof_matches_reviewed_guest"], True)
        self.assertEqual(report["real_proof_status"], clock.PROVEN)


if __name__ == "__main__":
    unittest.main()
