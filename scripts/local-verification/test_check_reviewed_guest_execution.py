"""check_reviewed_guest_execution: every CPU execution output must equal its pin.

Synthetic stand-ins for the vkey and clock-proof binaries replay a prepared
record, so each comparison is exercised without building SP1 or a guest.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import check_reviewed_guest_execution as checker

FAKE_VKEY = textwrap.dedent("""\
    #!/usr/bin/env python3
    import hashlib, os, sys
    assert sys.argv[1] == "--elf", sys.argv
    open(os.environ["FAKE_CALLS"], "a").write("vkey\\n")
    data = open(sys.argv[2], "rb").read()
    print("ELF_SHA256=" + os.environ.get("FAKE_ELF_LINE", hashlib.sha256(data).hexdigest()))
    for line in os.environ["FAKE_VKEY_LINES"].split(","):
        print(line)
    sys.exit(int(os.environ.get("FAKE_VKEY_EXIT", "0")))
""")

FAKE_CLOCK_PROOF = textwrap.dedent("""\
    #!/usr/bin/env python3
    import os, shutil, sys
    open(os.environ["FAKE_CALLS"], "a").write("clock-proof\\n")
    args = sys.argv[1:]
    elf = args[args.index("--elf") + 1]
    assert "--no-prove" in args, args
    (directory,) = [a for a in args if not a.startswith("--") and a != elf]
    os.mkdir(directory)
    shutil.copyfile(elf, os.path.join(directory, "guest.elf"))
    shutil.copyfile(os.environ["FAKE_WITNESS"], os.path.join(directory, "clock.witness.bin"))
    shutil.copyfile(os.environ["FAKE_RECORD"], os.path.join(directory, "execution.json"))
    sys.exit(int(os.environ.get("FAKE_PROOF_EXIT", "0")))
""")


def sha(data):
    return hashlib.sha256(data).hexdigest()


ELF = b"\x7fELF synthetic reviewed guest"
VKEY = bytes(range(32))
WITNESS = b"DPCLK4\0\0 synthetic normal fixture"
COMMITMENT = "0x" + "c0" * 32
NEGATIVES = {"wrong-bounds": "a1" * 32, "wrong-count": "a2" * 32, "legacy-tuple": "a3" * 32}
CASES = {"epoch-refresh": {"witness_sha256": "b1" * 32, "commitment": "0x" + "d1" * 32},
         "phase-1-sink": {"witness_sha256": "b2" * 32, "commitment": "0x" + "d2" * 32}}


def record(cases=CASES):
    value = {"kind": "synthetic", "sdk_version": "6.1.0", "elf_sha256": sha(ELF), "witness_sha256": sha(WITNESS),
             "commitment": COMMITMENT, "native_guest_equal": True, "cycles": 123, "proof_generated": False,
             "setup_performed": False,
             "negatives": [{"name": name, "guest_exit": 1, "public_bytes": 0, "witness_sha256": digest}
                           for name, digest in NEGATIVES.items()]}
    if cases is not None:
        value["cases"] = [{"name": name, "guest_exit": 0, "native_guest_equal": True, "cycles": 7, **pins}
                          for name, pins in cases.items()]
    return value


class ReviewedGuestExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = self.tmp / "root"
        for directory in ("crates/perp-core/src", "crates/sp1-guest/src"):
            (self.root / directory).mkdir(parents=True)
        self.identity = self.root / "fixtures/reviewed"
        self.identity.mkdir(parents=True)
        (self.identity / "guest.elf").write_bytes(ELF)
        (self.identity / "program-vkey.bin").write_bytes(VKEY)
        (self.identity / "clock.witness.bin").write_bytes(WITNESS)
        self.bins = {}
        for name, text in (("vkey", FAKE_VKEY), ("clock-proof", FAKE_CLOCK_PROOF)):
            path = self.tmp / name
            path.write_text(text)
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
            self.bins[name] = path
        self.calls = self.tmp / "calls.log"
        self.calls.touch()
        self.witness = self.tmp / "produced.witness.bin"
        self.witness.write_bytes(WITNESS)
        self.record_path = self.tmp / "record.json"
        self.write_record(record())
        self.env = {"FAKE_CALLS": str(self.calls), "FAKE_WITNESS": str(self.witness),
                    "FAKE_RECORD": str(self.record_path), "FAKE_VKEY_LINES": "VKEY=0x" + VKEY.hex()}
        for target, values in ((checker.clock.REVIEWED_GUEST, {"elf": sha(ELF), "vkey": "0x" + VKEY.hex(),
                                                               "identity_dir": "fixtures/reviewed", "sources": {}}),
                               (checker.clock.REVIEWED_FIXTURE, {"witness_sha256": sha(WITNESS),
                                                                 "commitment": COMMITMENT,
                                                                 "negatives": dict(NEGATIVES),
                                                                 "cases": copy.deepcopy(CASES)})):
            patcher = patch.dict(target, values)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.runs = 0

    def write_record(self, value):
        self.record_path.write_text(json.dumps(value))

    def verify(self, **env):
        self.runs += 1
        output = self.tmp / f"out-{self.runs}"
        with patch.dict(os.environ, {**self.env, **env}):
            return checker.verify(self.bins["vkey"], self.bins["clock-proof"], output, root=self.root, timeout=60)

    def refuses(self, message, **env):
        with self.assertRaisesRegex(ValueError, message):
            self.verify(**env)

    def invoked(self):
        return self.calls.read_text().split()

    def test_matching_outputs_pass_and_record_evidence(self):
        evidence = self.verify()
        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(evidence["derived_setup_key"], {"elf_sha256": sha(ELF), "program_vkey": "0x" + VKEY.hex()})
        self.assertEqual(evidence["execution"], {"cycles": 123, "cases": {"epoch-refresh": 7, "phase-1-sink": 7},
                                                 "negatives": sorted(NEGATIVES)})
        self.assertIs(evidence["proof_generated"], False)
        written = json.loads((self.tmp / "out-1/verification.json").read_text())
        self.assertEqual(written, evidence)
        self.assertEqual(self.invoked(), ["vkey", "clock-proof"])

    def test_no_case_pinned_accepts_a_record_without_cases(self):
        checker.clock.REVIEWED_FIXTURE["cases"] = {}
        self.write_record(record(cases=None))
        self.assertEqual(self.verify()["execution"]["cases"], {})

    def test_derived_setup_key_must_be_the_reviewed_key(self):
        self.refuses("derived setup key differs", FAKE_VKEY_LINES="VKEY=0x" + "ee" * 32)
        self.refuses("exactly one VKEY line", FAKE_VKEY_LINES="noise")
        self.refuses("exactly one VKEY line", FAKE_VKEY_LINES="VKEY=0x" + VKEY.hex() + ",VKEY=0x" + VKEY.hex())
        self.refuses("an ELF other than the reviewed one", FAKE_ELF_LINE="ee" * 32)
        self.refuses("vkey exited 3", FAKE_VKEY_EXIT="3")
        self.assertNotIn("clock-proof", self.invoked())

    def test_failed_execution_refuses(self):
        self.refuses("clock-proof exited 1", FAKE_PROOF_EXIT="1")

    def test_normal_fixture_outputs_must_match(self):
        for field, bad, message in (("commitment", "0x" + "ee" * 32, "commitment differs"),
                                    ("witness_sha256", "ee" * 32, "witness differs"),
                                    ("native_guest_equal", False, "native and guest"),
                                    ("cycles", 0, "native and guest"),
                                    ("proof_generated", True, "must not prove"),
                                    ("setup_performed", True, "must not prove or run setup"),
                                    ("elf_sha256", "ee" * 32, "execution ELF differs"),
                                    ("sdk_version", "6.0.0", "SDK version")):
            value = record()
            value[field] = bad
            self.write_record(value)
            with self.subTest(field=field):
                self.refuses(message)
        value = record()
        del value["setup_performed"]
        self.write_record(value)
        self.refuses("must not prove or run setup")

    def test_produced_witness_must_be_the_committed_one(self):
        self.witness.write_bytes(WITNESS + b"\0")
        self.refuses("produced fixture witness differs")

    def test_every_negative_is_pinned_and_rejected(self):
        mutations = {
            "missing": lambda negatives: negatives.pop(),
            "extra": lambda negatives: negatives.append({**negatives[0], "name": "unpinned"}),
            "duplicate": lambda negatives: negatives.append(dict(negatives[0])),
            "accepted": lambda negatives: negatives[0].update(guest_exit=0),
            "public-bytes": lambda negatives: negatives[0].update(public_bytes=32),
            "witness": lambda negatives: negatives[0].update(witness_sha256="ee" * 32),
        }
        for label, mutate in mutations.items():
            value = record()
            mutate(value["negatives"])
            self.write_record(value)
            with self.subTest(mutation=label):
                self.refuses("negative")

    def test_every_case_is_pinned_and_succeeds(self):
        mutations = {
            "missing": lambda cases: cases.pop(),
            "extra": lambda cases: cases.append({**cases[0], "name": "unpinned"}),
            "rejected": lambda cases: cases[0].update(guest_exit=1),
            "native-differs": lambda cases: cases[0].update(native_guest_equal=False),
            "commitment": lambda cases: cases[0].update(commitment="0x" + "ee" * 32),
            "witness": lambda cases: cases[0].update(witness_sha256="ee" * 32),
        }
        for label, mutate in mutations.items():
            value = record()
            mutate(value["cases"])
            self.write_record(value)
            with self.subTest(mutation=label):
                self.refuses("case")
        self.write_record(record(cases=None))
        self.refuses("has no cases but REVIEWED_FIXTURE pins some")

    def test_committed_identity_is_checked_before_any_binary_runs(self):
        for name, data, message in (("guest.elf", ELF + b"\0", "guest.elf differs"),
                                    ("program-vkey.bin", bytes(32), "program-vkey.bin differs"),
                                    ("clock.witness.bin", b"other", "clock.witness.bin differs")):
            original = (self.identity / name).read_bytes()
            (self.identity / name).write_bytes(data)
            with self.subTest(file=name):
                self.refuses(message)
            (self.identity / name).write_bytes(original)
        (self.identity / "guest.elf").unlink()
        self.refuses("missing")
        self.assertEqual(self.invoked(), [])

    def test_changed_guest_source_or_layout_refuses_before_any_binary_runs(self):
        source = self.root / "crates/perp-core/src/lib.rs"
        source.write_text("reviewed")
        checker.clock.REVIEWED_GUEST["sources"] = {"crates/perp-core/src/lib.rs": sha(b"reviewed")}
        self.verify()
        source.write_text("changed")
        self.refuses("guest source changed")
        (self.root / "crates/perp-core/src/new.rs").write_text("unreviewed")
        self.refuses("source layout changed")
        self.assertEqual(self.invoked(), ["vkey", "clock-proof"])

    def test_malformed_pins_and_reused_output_refuse(self):
        checker.clock.REVIEWED_FIXTURE["cases"] = {"bad": {"witness_sha256": "b1" * 32}}
        self.refuses("malformed REVIEWED_FIXTURE cases")
        checker.clock.REVIEWED_FIXTURE["cases"] = copy.deepcopy(CASES)
        checker.clock.REVIEWED_FIXTURE["negatives"] = {}
        self.refuses("malformed REVIEWED_FIXTURE negatives")
        checker.clock.REVIEWED_FIXTURE["negatives"] = dict(NEGATIVES)
        (self.tmp / "out-3").mkdir()
        self.refuses("fresh output directory required")
        self.assertEqual(self.invoked(), [])

    def test_ci_job_runs_this_checker_on_the_reviewed_records(self):
        ci = (checker.ROOT / ".github/workflows/ci.yml").read_text()
        job = ci.split("  reviewed-guest-execution:", 1)[1].split("\n  contracts:", 1)[0]
        self.assertIn("name: reviewed guest execution (CPU)", job)
        self.assertIn("timeout-minutes:", job)
        self.assertIn("--bin vkey --bin clock-proof", job)
        self.assertIn("scripts/local-verification/check_reviewed_guest_execution.py", job)
        # Never green by skipping: no continue-on-error, no dependency that could
        # skip the job, and no conditional step other than the evidence upload.
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("needs:", job)
        conditions = [line.strip() for line in job.splitlines() if line.strip().startswith("if:")]
        self.assertEqual(conditions, ["if: always()"])


if __name__ == "__main__":
    unittest.main()
