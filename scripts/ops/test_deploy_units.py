"""deploy/ stays consistent with scripts/ops: commands, arguments, events, no values."""
import importlib
import re
import shlex
import unittest
from pathlib import Path

import ops_notify

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
OPS_LIB = "/usr/local/lib/darkperp-ops/"


def unit(name):
    """Minimal systemd unit reader: {section: [(key, value), ...]} keeping repeats."""
    sections, current = {}, None
    for raw in (DEPLOY / "systemd" / name).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            current = sections.setdefault(line.strip("[]"), [])
            continue
        key, _, value = line.partition("=")
        current.append((key.strip(), value.strip()))
    return sections


def values(sections, section, key):
    return [v for k, v in sections.get(section, []) if k == key]


def units():
    return sorted(p.name for p in (DEPLOY / "systemd").iterdir())


class Units(unittest.TestCase):
    def test_expected_units_exist(self):
        self.assertEqual(units(), [
            "darkperp-backup.service",
            "darkperp-backup.timer",
            "darkperp-gateway.service",
            "darkperp-monitor.service",
            "darkperp-monitor.timer",
            "darkperp-notify@.service",
        ])

    def test_gateway_runs_unprivileged_and_hardened(self):
        s = unit("darkperp-gateway.service")
        self.assertEqual(values(s, "Service", "User"), ["darkperp"])
        self.assertEqual(values(s, "Service", "ExecStart"), ["/usr/local/bin/darkperp-gateway"])
        self.assertEqual(values(s, "Service", "EnvironmentFile"), ["/etc/darkperp/gateway.env"])
        for key, value in [
            ("NoNewPrivileges", "yes"), ("ProtectSystem", "strict"), ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"), ("CapabilityBoundingSet", ""), ("ReadWritePaths", "/var/lib/darkperp"),
            ("KillSignal", "SIGTERM"), ("UMask", "0077"),
            # Without it systemd 255 passes through "failed" on every automatic
            # restart and fires OnFailure= each time (drill: 4 alerts in 18 s).
            ("RestartMode", "direct"),
        ]:
            self.assertEqual(values(s, "Service", key), [value], key)
        self.assertEqual(values(s, "Unit", "OnFailure"), ["darkperp-notify@gateway_service_failed.service"])

    def test_every_on_failure_event_is_a_known_one_shot_event(self):
        for name in units():
            for target in values(unit(name), "Unit", "OnFailure"):
                match = re.fullmatch(r"darkperp-notify@([a-z_]+)\.service", target)
                self.assertIsNotNone(match, f"{name}: {target}")
                self.assertIn(match.group(1), ops_notify.ONE_SHOT_EVENTS, name)

    def test_ops_commands_point_at_repo_scripts_with_accepted_arguments(self):
        checked = 0
        for name in units():
            for command in values(unit(name), "Service", "ExecStart"):
                argv = shlex.split(command.replace("%i", ops_notify.ONE_SHOT_EVENTS[0]))
                if not argv[0].startswith(OPS_LIB):
                    continue
                script = Path(argv[0][len(OPS_LIB):])
                self.assertTrue((ROOT / "scripts" / "ops" / script).is_file(), f"{name}: {script}")
                module = importlib.import_module(script.stem)
                module.build_parser().parse_args(argv[1:])
                checked += 1
        self.assertEqual(checked, 3)

    def test_timers_trigger_existing_services(self):
        for name in units():
            if name.endswith(".timer"):
                service = values(unit(name), "Timer", "Unit") or [name.replace(".timer", ".service")]
                self.assertIn(service[0], units(), name)


class MonitorL1Settings(unittest.TestCase):
    def test_monitor_takes_l1_settings_from_ops_env_and_thresholds_from_its_command(self):
        s = unit("darkperp-monitor.service")
        self.assertEqual(values(s, "Service", "EnvironmentFile"), ["-/etc/darkperp/ops.env"])
        argv = shlex.split(values(s, "Service", "ExecStart")[0])
        for flag, value in [("--liveness-low-percent", "50"), ("--challenge-age-blocks", "900"),
                            ("--l1-failures", "3")]:
            self.assertIn(flag, argv)
            self.assertEqual(argv[argv.index(flag) + 1], value, flag)
        # Addresses and URLs are host values: they live in ops.env, not in the unit.
        self.assertNotIn("--settlement", argv)
        self.assertEqual([a for a in argv if a.startswith("http")], ["http://127.0.0.1:8080"])

    def test_the_rpc_url_can_only_come_from_the_environment(self):
        # It may carry a provider key, so it must never sit on a command line.
        import gateway_monitor
        options = {o for action in gateway_monitor.build_parser()._actions for o in action.option_strings}
        self.assertEqual([o for o in options if "rpc" in o.lower()], [])

    def test_ops_env_template_names_every_monitor_l1_variable(self):
        import gateway_monitor
        names = {line.split("=", 1)[0] for line in (DEPLOY / "env" / "ops.env.example").read_text().splitlines()
                 if line and not line.startswith("#")}
        self.assertEqual(set(gateway_monitor.L1_ENV), {"DARKPERP_L1_RPC", "DARKPERP_SETTLEMENT"})
        self.assertLessEqual(set(gateway_monitor.L1_ENV), names)


class Templates(unittest.TestCase):
    def test_env_templates_carry_names_only(self):
        for path in sorted((DEPLOY / "env").iterdir()):
            for raw in path.read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                self.assertRegex(line, r"^[A-Z][A-Z0-9_]*=$", f"{path.name}: value present in {line!r}")


if __name__ == "__main__":
    unittest.main()
