"""verify_funds_replay's negative controls expect the refusals replay-funds prints.

The harness counts a negative control only when replay-funds fails with the text
of the intended refusal. These tests read those texts from the Rust sources (the
binary's own messages, perp-core's framing magic and the prover's error
variants), so a changed message fails here instead of turning a correct refusal
into a reported infrastructure error in the slower CI replay step.
"""
from pathlib import Path
import re
import unittest

import verify_funds_replay as harness

ROOT = Path(__file__).resolve().parents[2]
REPLAY_FUNDS = ROOT / "crates/sp1-host/src/bin/replay-funds.rs"


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


if __name__ == "__main__":
    unittest.main()
