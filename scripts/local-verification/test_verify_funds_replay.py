"""verify_funds_replay's negative controls expect the refusals replay-funds prints.

The harness counts a negative control only when replay-funds fails with the text
of the intended refusal. These tests read those texts from the Rust sources (the
binary's own messages, perp-core's framing magic and the prover's error
variants), so a changed message fails here instead of turning a correct refusal
into a reported infrastructure error in the slower CI replay step.

They also tie the harness's pins of the committed lifecycle export to its files,
to the manifest that links them, to the injected clock of the test that wrote
them, and to the directory's README.
"""
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import verify_funds_replay as harness

ROOT = Path(__file__).resolve().parents[2]
REPLAY_FUNDS = ROOT / "crates/sp1-host/src/bin/replay-funds.rs"
LIFECYCLE = ROOT / harness.LIFECYCLE_DIR
FUNDS_LIFECYCLE_TESTS = "crates/gateway/src/funds_lifecycle_tests.rs"


def source(relative):
    return (ROOT / relative).read_text()


def prover_error_variants():
    """The variant names of `prover::ProverError`."""
    body = re.search(r"pub enum ProverError \{(.*?)\n\}", source("crates/prover/src/lib.rs"), re.S)
    assert body, "ProverError enum not found"
    lines = [line.split("//")[0].strip() for line in body.group(1).splitlines()]
    return {re.match(r"([A-Z]\w*)", line).group(1) for line in lines if re.match(r"[A-Z]\w*\s*[,(]", line)}


def string_literals(text):
    """Every plain Rust string literal in `text`, unescaped for `\\"` only."""
    return {value.replace('\\"', '"') for value in re.findall(r'"((?:[^"\\]|\\.)*)"', text)}


class RefusalTextsComeFromTheBinary(unittest.TestCase):
    def test_witness_refusal_is_the_strict_decode_expect_text(self):
        text = REPLAY_FUNDS.read_text()
        found = re.findall(r"decode_clock_witness\(&bytes\)\s*\.expect\(\s*\"([^\"]+)\"\s*\)", text)
        self.assertEqual(found, [harness.WITNESS_REFUSAL])

    def test_every_expected_text_is_a_message_the_binary_can_print(self):
        literals = string_literals(REPLAY_FUNDS.read_text())
        variants = prover_error_variants()
        self.assertTrue({"UnboundWitness", "WitnessDecode"} <= variants)
        for name, expected in harness.CASES:
            with self.subTest(case=name):
                if expected.startswith(harness.WITNESS_REFUSAL + ": "):
                    # `Result::expect` panics with "<message>: <Debug of the error>".
                    self.assertIn(expected.removeprefix(harness.WITNESS_REFUSAL + ": "), variants)
                elif expected == harness.ASSERT_EQ_REFUSAL:
                    self.assertIn("assert_eq!", REPLAY_FUNDS.read_text())
                else:
                    self.assertIn(expected, literals)

    def test_case_names_are_unique_and_every_decoder_case_is_a_case(self):
        names = [name for name, _ in harness.CASES]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(set(harness.DECODER_CASES) <= set(names))


class WitnessMutations(unittest.TestCase):
    """Each decoder case produces the input class whose refusal it expects."""

    def test_wire_magic_is_perp_core_framing(self):
        magic = re.findall(r'pub const WIRE_MAGIC: &\[u8; 8\] = b"([^"]+)";', source("crates/perp-core/src/clock.rs"))
        self.assertEqual(len(magic), 1)
        self.assertEqual(harness.WIRE_MAGIC, magic[0].replace("\\0", "\0").encode())

    def test_each_mutation_reaches_its_decoder_refusal(self):
        raw = harness.WIRE_MAGIC + bytes(range(40))
        expected = dict(harness.CASES)
        for name in harness.DECODER_CASES:
            with self.subTest(case=name):
                changed = harness.witness_mutation(name, raw)
                self.assertNotEqual(changed, raw)
                framed = changed.startswith(harness.WIRE_MAGIC)
                # Unframed input is refused before any decode; framed input only by
                # a body that does not decode exactly.
                refusal = "WitnessDecode" if framed else "UnboundWitness"
                self.assertEqual(expected[name], harness.WITNESS_REFUSAL + ": " + refusal)
        self.assertEqual(harness.witness_mutation("trailing-witness", raw), raw + b"\0")
        self.assertEqual(harness.witness_mutation("magic-only-witness", raw), harness.WIRE_MAGIC)
        self.assertEqual(harness.witness_mutation("legacy-witness", raw), raw[8:])
        self.assertEqual(harness.witness_mutation("dpclk2-witness", raw), b"DPCLK2\0\0" + raw[8:])

    def test_an_unframed_export_is_refused_by_the_harness(self):
        with self.assertRaises(ValueError):
            harness.witness_mutation("trailing-witness", b"DPCLK2\0\0body")
        with self.assertRaises(ValueError):
            harness.witness_mutation("changed-witness", harness.WIRE_MAGIC + b"body")


def rust_u64(name):
    """The value of `const <name>: u64 = ...;` in the funds lifecycle test."""
    found = re.findall(r"^const %s: u64 = ([0-9_]+);" % name, source(FUNDS_LIFECYCLE_TESTS), re.M)
    assert len(found) == 1, name
    return int(found[0].replace("_", ""))


def pinned_files():
    return dict(harness.LIFECYCLE_WITNESSES, **{"lifecycle.json": harness.LIFECYCLE_MANIFEST_SHA256})


class CommittedLifecycleExport(unittest.TestCase):
    """The pins describe the committed export, and the harness enforces them."""

    def manifest(self):
        return json.loads((LIFECYCLE / "lifecycle.json").read_text())

    def test_the_committed_export_matches_its_pins(self):
        harness.check_committed_export(LIFECYCLE)

    def test_the_manifest_links_every_pinned_witness(self):
        manifest = self.manifest()
        self.assertEqual(manifest["status"], "PASS")
        self.assertIs(manifest["syntheticWitnesses"], True)
        batches = manifest["batches"]
        # replay-funds replays exactly the four wallet windows, in order.
        self.assertEqual([batch["batch"] for batch in batches], [0, 1, 2, 3])
        windows = batches + [manifest["keepalive"]]
        self.assertIs(manifest["keepalive"]["keepalive"], True)
        self.assertEqual([window["clock"]["filename"] for window in windows], list(harness.LIFECYCLE_WITNESSES))
        for window in windows:
            name = window["clock"]["filename"]
            with self.subTest(witness=name):
                self.assertEqual(window["clock"]["witnessSha256"], "0x" + harness.LIFECYCLE_WITNESSES[name])
                self.assertEqual(window["clock"]["witnessBytes"], (LIFECYCLE / name).stat().st_size)

    def test_the_manifest_records_the_injected_clock(self):
        epoch_ms = rust_u64("CLOCK_EPOCH_MS")
        interval = rust_u64("BLOCK_INTERVAL_SECS")
        clock = self.manifest()["injectedClock"]
        self.assertEqual(clock["epochMs"], epoch_ms)
        self.assertEqual(clock["blockIntervalSecs"], interval)
        self.assertEqual(clock["chainGenesisTimestamp"] * 1000, epoch_ms)
        manifest = self.manifest()
        anchors = [window["clock"]["anchoredAtMs"] for window in manifest["batches"] + [manifest["keepalive"]]]
        # Every window is anchored at a block of the owned chain, after its genesis.
        self.assertEqual(anchors, sorted(set(anchors)))
        for anchor in anchors:
            self.assertGreater(anchor, epoch_ms)
            self.assertEqual((anchor - epoch_ms) % (interval * 1000), 0)

    def test_every_witness_is_wire_framed(self):
        for name in harness.LIFECYCLE_WITNESSES:
            with self.subTest(witness=name):
                self.assertTrue((LIFECYCLE / name).read_bytes().startswith(harness.WIRE_MAGIC))

    def test_the_readme_lists_the_pins(self):
        text = (LIFECYCLE / harness.LIFECYCLE_README).read_text()
        block = text.split("\n## SHA-256\n", 1)[1]
        listed = dict((name, value) for value, name in re.findall(r"^    ([0-9a-f]{64})  (\S+)$", block, re.M))
        self.assertEqual(listed, pinned_files())

    def test_a_changed_missing_or_extra_file_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp) / "lifecycle"
            shutil.copytree(LIFECYCLE, copy)
            harness.check_committed_export(copy)
            for name in pinned_files():
                with self.subTest(changed=name):
                    original = (copy / name).read_bytes()
                    (copy / name).write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                    with self.assertRaisesRegex(ValueError, "committed lifecycle export changed"):
                        harness.check_committed_export(copy)
                    (copy / name).write_bytes(original)
                with self.subTest(missing=name):
                    (copy / name).rename(copy / (name + ".moved"))
                    with self.assertRaisesRegex(ValueError, "files differ from the pins"):
                        harness.check_committed_export(copy)
                    (copy / (name + ".moved")).rename(copy / name)
                with self.subTest(symlink=name):
                    # A link to the pinned bytes is still refused.
                    outside = Path(temp) / name
                    (copy / name).rename(outside)
                    (copy / name).symlink_to(outside)
                    with self.assertRaisesRegex(ValueError, "not a regular file"):
                        harness.check_committed_export(copy)
                    (copy / name).unlink()
                    outside.rename(copy / name)
            (copy / "batch-4.witness.bin").write_bytes(harness.WIRE_MAGIC)
            with self.assertRaisesRegex(ValueError, "files differ from the pins"):
                harness.check_committed_export(copy)
            (copy / "batch-4.witness.bin").unlink()
            harness.check_committed_export(copy)

    def test_the_harness_refuses_a_changed_committed_export_before_any_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            committed = root / harness.LIFECYCLE_DIR
            shutil.copytree(LIFECYCLE, committed)
            witness = committed / "batch-1.witness.bin"
            witness.write_bytes(witness.read_bytes() + b"\0")
            binary = root / "replay-funds"
            binary.write_bytes(b"")
            output = root / "evidence"
            argv = ["verify_funds_replay.py", "--binary", str(binary), "--witness-dir", str(committed),
                    "--output-dir", str(output)]
            with mock.patch.object(harness, "ROOT", root), mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(harness.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "committed lifecycle export changed: batch-1.witness.bin"):
                    harness.main()
            run.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
