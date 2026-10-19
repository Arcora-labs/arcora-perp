"""Explicit synthetic expectations and public snapshots; no service, key or network."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import service_identity_preflight as preflight


def checksum(value):
    return hashlib.sha256(preflight.identity.canonical(value)).hexdigest()


def build():
    return {"schema": "arcora-service-build-identity/v1", "algorithm": "sha256-canonical-source-map-v1",
            "source_files": 400, "source_sha256": "aa" * 32}


def program():
    return {"sdk_version": "6.1.0", "elf_sha256": "bb" * 32, "elf_bytes": 100,
            "program_vkey": "0x" + "cc" * 32, "supported_witness_domains": ["DPCLK4"]}


def gateway_config():
    return {"chain_id": 84532, "vault": "0x" + "11" * 20, "gateway_signer": "0x" + "22" * 20,
            "l1": {"settlement": "0x" + "33" * 20, "vault": "0x" + "11" * 20,
                   "token": "0x" + "44" * 20, "clock": {"chain_id": 84532, "verifier": "0x" + "55" * 20}},
            "prover_configured": True, "clocked_prover_configured": True,
            "candidate_archive_required": True,
            "candidate_archive": {"policy_binding": "0x" + "66" * 32, "oracle_policy_hash": "0x" + "77" * 32}}


def prover_config():
    return {"measurement": "0x" + "ab" * 32, "dev_insecure": False,
            "admission": {"max_concurrent": 1, "body_bytes": 1024, "body_timeout_ms": 30000}}


def expectations():
    # Independently authored declared configurations, NOT copied from responses.
    expected_gateway = {"chain_id": 84532, "vault": "0x" + "11" * 20, "gateway_signer": "0x" + "22" * 20,
        "l1": {"settlement": "0x" + "33" * 20, "vault": "0x" + "11" * 20, "token": "0x" + "44" * 20,
               "clock": {"chain_id": 84532, "verifier": "0x" + "55" * 20}},
        "prover_configured": True, "clocked_prover_configured": True, "candidate_archive_required": True,
        "candidate_archive": {"policy_binding": "0x" + "66" * 32, "oracle_policy_hash": "0x" + "77" * 32}}
    expected_prover = {"measurement": "0x" + "ab" * 32, "dev_insecure": False,
                       "admission": {"max_concurrent": 1, "body_bytes": 1024, "body_timeout_ms": 30000}}
    return {"schema": preflight.EXPECTATIONS_SCHEMA,
            "gateway": {"build": build(), "program": None, "public_config_sha256": checksum(expected_gateway)},
            "prover": {"build": build(), "program": program(), "public_config_sha256": checksum(expected_prover)}}


def snapshot(service):
    config = gateway_config() if service == "gateway" else prover_config()
    return {"schema": preflight.SERVICE_SCHEMA, "service": service,
            "evidence_kind": "self_reported_unattested", "build": build(),
            "program": None if service == "gateway" else program(), "public_config": config,
            "public_config_sha256": checksum(config),
            "capabilities": {"candidate_submission_supported": False, "candidate_submission_enabled": False},
            "scope": {"running_services_attested": False, "operator_policy_approved": False,
                      "proof_generated_by_identity_request": False, "release_gate": "HOLD"}}


class PreflightTests(unittest.TestCase):
    def positive(self):
        values = (expectations(), snapshot("gateway"), snapshot("prover"))
        result = preflight.compare_snapshots(*values)
        self.assertEqual(result["status"], "DECLARATIONS_MATCH", result)
        self.assertFalse(result["candidate_compatibility"]["compatible"])
        self.assertEqual(result["candidate_compatibility"]["status"], "REFUSED")
        self.assertEqual(result["scope"]["release_gate"], "HOLD")
        self.assertFalse(result["scope"]["running_services_attested"])
        return values

    def negative(self, mutation):
        # Every semantic refusal starts from a separately proven full baseline.
        values = self.positive()
        mutation(*values)
        result = preflight.compare_snapshots(*values)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertEqual(result["scope"]["release_gate"], "HOLD")
        self.assertNotIn("input_sha256", result)

    def test_full_match_is_self_report_only_and_candidate_refused(self):
        self.positive()

    def test_foreign_versions_and_wrong_roles_refuse(self):
        for mutation in (
            lambda e, g, p: e.update(schema="arcora-clock-release/v1"),
            lambda e, g, p: g.update(schema="arcora-public-service-identity/v2"),
            lambda e, g, p: p.update(service="gateway"),
            lambda e, g, p: g.update(service="prover"),
            lambda e, g, p: g.update(evidence_kind="attested")):
            self.negative(mutation)

    def test_missing_or_private_fields_never_default_or_echo(self):
        for mutation in (lambda e, g, p: e.pop("prover"), lambda e, g, p: g.pop("build"),
                         lambda e, g, p: g["public_config"].update(seal_root="synthetic-private-value"),
                         lambda e, g, p: p.update(token="synthetic-private-value"),
                         lambda e, g, p: e.update(automatic_expectations=True)):
            self.negative(mutation)

    def test_each_build_field_and_type_mismatch_refuses(self):
        for field, value in (("schema", "foreign"), ("algorithm", "sha256"), ("source_files", 401),
                             ("source_files", True), ("source_files", 0), ("source_files", 8193),
                             ("source_sha256", "dd" * 32), ("source_sha256", "0x" + "aa" * 32),
                             ("source_sha256", "AA" * 32)):
            self.negative(lambda e, g, p, f=field, v=value: p["build"].update({f: v}))

    def test_each_program_field_mismatch_refuses(self):
        for field, value in (("elf_sha256", "dd" * 32), ("elf_bytes", 101), ("elf_bytes", True),
                             ("elf_bytes", 0), ("program_vkey", "0x" + "dd" * 32),
                             ("sdk_version", "6.2.0"), ("supported_witness_domains", ["DPCLK3"]),
                             ("supported_witness_domains", ["legacy"]),
                             ("supported_witness_domains", ["DPCLK2"]),
                             ("supported_witness_domains", ["legacy", "DPCLK2"]),
                             ("supported_witness_domains", ["legacy", "DPCLK4"]),
                             ("supported_witness_domains", ["DPCLK4", "DPCLK4"]),
                             ("supported_witness_domains", ["DPCLK4\0\0"]),
                             ("supported_witness_domains", [])):
            self.negative(lambda e, g, p, f=field, v=value: p["program"].update({f: v}))
        self.negative(lambda e, g, p: g.update(program=program()))
        self.negative(lambda e, g, p: p.update(program=None))

    def test_witness_domain_is_the_reviewed_clock_framing(self):
        # Read from perp-core's WIRE_MAGIC; the unframed tuple is never a domain.
        self.assertEqual(preflight.witness_domains(), ["DPCLK4"])
        self.assertNotIn("legacy", preflight.witness_domains())
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / preflight.CLOCK_SOURCE
            source.parent.mkdir(parents=True)
            source.write_text('pub const WIRE_MAGIC: &[u8; 8] = b"DPCLK9\\0\\0";\n')
            self.assertEqual(preflight.witness_domains(directory), ["DPCLK9"])
            for text in ('pub const WIRE_MAGIC: &[u8; 8] = b"\\0\\0\\0\\0\\0\\0\\0\\0";\n',
                         'pub const WIRE_MAGIC: &[u8; 8] = b"DP\\0CLK4\\0";\n', "no definition\n"):
                source.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    preflight.witness_domains(directory)

    def test_hash_is_recomputed_before_comparing_independent_expectation(self):
        self.negative(lambda e, g, p: g["public_config"].update(chain_id=8453))
        def forged(e, g, p):
            g["public_config"]["chain_id"] = 8453
            g["public_config_sha256"] = checksum(g["public_config"])
        self.negative(forged)
        self.negative(lambda e, g, p: e["gateway"].update(public_config_sha256="dd" * 32))

    def test_scope_and_capability_promotions_or_bool_aliases_refuse(self):
        for field in preflight.ENDPOINT_SCOPE:
            self.negative(lambda e, g, p, f=field: p["scope"].update({f: "PASS" if f == "release_gate" else True}))
        for field in preflight.CAPABILITIES:
            for value in (True, 0):
                self.negative(lambda e, g, p, f=field, v=value: g["capabilities"].update({f: v}))
        self.negative(lambda e, g, p: g["scope"].update(running_services_attested=0))

    def test_gateway_types_addresses_and_required_archive_refuse(self):
        for field, value in (("chain_id", True), ("chain_id", 0), ("chain_id", 2**64),
                             ("vault", "0x1"), ("gateway_signer", "0x" + "00" * 20),
                             ("prover_configured", 1), ("candidate_archive", None)):
            self.negative(lambda e, g, p, f=field, v=value: g["public_config"].update({f: v}))
        self.negative(lambda e, g, p: g["public_config"]["l1"].update(settlement="0x" + "00" * 20))
        self.negative(lambda e, g, p: g["public_config"].update(prover_configured=False))

    def test_prover_admission_types_and_bounds_refuse(self):
        for field, value in (("max_concurrent", True), ("max_concurrent", 0), ("max_concurrent", 9),
                             ("body_bytes", 0), ("body_bytes", 512 * 1024 * 1024 + 1),
                             ("body_timeout_ms", 999), ("body_timeout_ms", 1001), ("body_timeout_ms", 300001)):
            self.negative(lambda e, g, p, f=field, v=value: p["public_config"]["admission"].update({f: v}))
        self.negative(lambda e, g, p: p["public_config"].update(dev_insecure=0))

    def test_semantic_input_change_during_comparison_refuses(self):
        values = self.positive()
        original = preflight.validate_snapshot
        def changing(value, service):
            original(value, service)
            values[0]["gateway"]["build"]["source_files"] = 401
        with patch.object(preflight, "validate_snapshot", side_effect=changing):
            self.assertEqual(preflight.compare_snapshots(*values)["status"], "BLOCKED")

    def test_json_duplicate_depth_nonfinite_and_bound_refuse(self):
        self.positive()
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '[' * 65 + '0' + ']' * 65):
            with self.assertRaises(ValueError): preflight.identity.decode_json(raw)
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            path = Path(directory) / 'large.json'
            path.write_bytes(b' ' * (preflight.MAX_INPUT_BYTES + 1))
            with self.assertRaises(ValueError): preflight.load_input(path)

    def files(self, directory):
        values = self.positive()
        paths = [Path(directory) / (name + '.json') for name in ('expectations', 'gateway', 'prover')]
        for path, value in zip(paths, values): path.write_text(json.dumps(value))
        return paths

    def test_offline_public_files_match_and_output_never_clobbered(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            paths = self.files(directory); output = Path(directory) / 'result.json'
            self.assertEqual(preflight.run_files(*paths, output)["status"], "DECLARATIONS_MATCH")
            original = output.read_bytes()
            with self.assertRaises(ValueError): preflight.run_files(*paths, output)
            self.assertEqual(output.read_bytes(), original)

    def test_file_change_before_publication_writes_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            paths = self.files(directory); output = Path(directory) / 'result.json'
            original = preflight.compare_snapshots
            def changing(*values):
                matched = original(*values)
                self.assertEqual(matched['status'], 'DECLARATIONS_MATCH')
                paths[1].write_text(paths[1].read_text() + '\n')
                return matched
            with patch.object(preflight, 'compare_snapshots', side_effect=changing):
                self.assertEqual(preflight.run_files(*paths, output)['status'], 'BLOCKED')
            self.assertEqual(json.loads(output.read_text())['status'], 'BLOCKED')

    def test_private_paths_and_symlinks_refuse_before_reads(self):
        self.positive()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            path = Path(directory) / '.env'
            with patch.object(preflight.identity, 'read_json') as read:
                with self.assertRaises(ValueError): preflight.load_input(path)
                read.assert_not_called()
            target = Path(directory) / 'public.json'; target.write_text('{}')
            link = Path(directory) / 'alias.json'; link.symlink_to(target)
            with self.assertRaises(ValueError): preflight.load_input(link)

    def test_cli_unknown_arguments_never_echo_and_has_no_http_mode(self):
        self.positive()
        script = Path(preflight.__file__)
        for arguments in (['--private-key', 'synthetic-private-value'], ['--rpc', 'synthetic-endpoint']):
            completed = subprocess.run([sys.executable, str(script), *arguments], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn('synthetic-private-value', completed.stdout + completed.stderr)
            self.assertNotIn('synthetic-endpoint', completed.stdout + completed.stderr)

    def test_current_nullable_development_config_matches_when_explicitly_expected(self):
        expected, gateway, prover = self.positive()
        minimal = {'chain_id': 84532, 'vault': '0x' + '00' * 20, 'gateway_signer': '0x' + '22' * 20,
                   'l1': None, 'prover_configured': False, 'clocked_prover_configured': False,
                   'candidate_archive_required': False, 'candidate_archive': None}
        declared_minimal = {'chain_id': 84532, 'vault': '0x' + '00' * 20, 'gateway_signer': '0x' + '22' * 20,
                           'l1': None, 'prover_configured': False, 'clocked_prover_configured': False,
                           'candidate_archive_required': False, 'candidate_archive': None}
        gateway['public_config'] = minimal; gateway['public_config_sha256'] = checksum(minimal)
        expected['gateway']['public_config_sha256'] = checksum(declared_minimal)
        self.assertEqual(preflight.compare_snapshots(expected, gateway, prover)['status'], 'DECLARATIONS_MATCH')


if __name__ == '__main__':
    unittest.main()
