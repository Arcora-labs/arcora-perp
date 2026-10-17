"""Repository policy contract; offline guards are not a live merge-denial drill."""
import copy
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def validate(policy):
    assert policy["enforcement"] == "active"
    assert policy["target"] == "branch"
    assert policy["bypass_actors"] == []
    assert policy["conditions"]["ref_name"] == {"include": ["refs/heads/main"], "exclude": []}
    rules = {r["type"]: r.get("parameters", {}) for r in policy["rules"]}
    assert "deletion" in rules and "non_fast_forward" in rules
    review = rules["pull_request"]
    assert review["required_approving_review_count"] >= 1
    assert review["dismiss_stale_reviews_on_push"]
    assert review["require_last_push_approval"]
    assert review["required_review_thread_resolution"]
    checks = rules["required_status_checks"]
    assert checks["strict_required_status_checks_policy"]
    required = {c["context"]: c["integration_id"] for c in checks["required_status_checks"]}
    expected = {"rust (lint, 1.99)", "rust (workspace)", "prover crates (excluded, typecheck)",
                "contracts (foundry)", "frontend (vite)", "dependency advisories",
                "release regression", "foundry release gate", "gateway RPC, crash and alert drills",
                "frontend release gate", "prover source / deployment binding"}
    assert set(required) >= expected
    assert all(required[name] == 15368 for name in expected)


class RepositoryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / ".github/main-ruleset.json").read_text())

    def test_reviewed_policy(self):
        validate(self.policy)

    def test_refuses_disabled_bypass_missing_proof_check_or_forged_check_issuer(self):
        cases = []
        p = copy.deepcopy(self.policy); p["enforcement"] = "disabled"; cases.append(p)
        p = copy.deepcopy(self.policy); p["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]; cases.append(p)
        p = copy.deepcopy(self.policy)
        checks = p["rules"][-1]["parameters"]["required_status_checks"]
        checks[:] = [c for c in checks if c["context"] != "foundry release gate"]; cases.append(p)
        p = copy.deepcopy(self.policy); p["rules"][-1]["parameters"]["required_status_checks"][0]["integration_id"] = 0; cases.append(p)
        for policy in cases:
            with self.subTest(policy=policy), self.assertRaises(AssertionError):
                validate(policy)

    def test_required_workflows_run_on_every_pull_request(self):
        for name in ("ci.yml", "a11-release-evidence.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text()
            trigger = workflow.split("jobs:", 1)[0]
            self.assertIn("  pull_request:", trigger)
            self.assertNotIn("    paths:", trigger)
            self.assertNotIn("    paths-ignore:", trigger)

    def test_every_opt_in_anvil_suite_runs_in_a_workflow(self):
        # An `ARCORA_RUN_*` gate that no workflow sets is a suite CI always skips.
        import re
        gates = set()
        for path in (ROOT / "scripts").rglob("*.py"):
            gates.update(re.findall(r"environ\.get\(\s*[\"'](ARCORA_RUN_[A-Z0-9_]+)[\"']", path.read_text()))
        self.assertIn("ARCORA_RUN_CLAIM_ANVIL", gates)
        workflows = "\n".join(p.read_text() for p in (ROOT / ".github/workflows").glob("*.yml"))
        for gate in sorted(gates):
            with self.subTest(gate=gate):
                self.assertRegex(workflows, rf"\b{gate}=1\b")


if __name__ == "__main__":
    unittest.main()
