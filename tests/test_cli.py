"""Tests for the command line interface."""

import io
import json
import os
import tempfile
import unittest

from tests.helpers import CLEAN, SUSPICIOUS

from persistwatch.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class ExitCodeTests(unittest.TestCase):
    def test_clean_directory_exits_zero(self):
        code, out, _err = run_cli(CLEAN, "--recent-days", "0")
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("No findings", out)

    def test_suspicious_directory_exits_one(self):
        code, out, _err = run_cli(SUSPICIOUS, "--recent-days", "0")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("update-notifier.service", out)

    def test_exit_zero_flag_suppresses_the_failure_code(self):
        code, _out, _err = run_cli(SUSPICIOUS, "--recent-days", "0", "--exit-zero")
        self.assertEqual(code, EXIT_CLEAN)

    def test_no_arguments_is_a_usage_error(self):
        code, _out, err = run_cli()
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("at least one directory", err)

    def test_missing_directory_is_an_error(self):
        code, _out, err = run_cli("/nonexistent/persistwatch/path")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not a directory", err)

    def test_unknown_disabled_rule_is_an_error(self):
        code, _out, err = run_cli(CLEAN, "--disable", "no_such_rule")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("unknown rule", err)


class TextReportTests(unittest.TestCase):
    def test_header_reports_what_was_scanned(self):
        _code, out, _err = run_cli(SUSPICIOUS, "--recent-days", "0")
        self.assertIn("persistwatch report", out)
        self.assertIn("units parsed : 7", out)
        self.assertIn(SUSPICIOUS, out)

    def test_report_lists_the_attack_techniques(self):
        _code, out, _err = run_cli(SUSPICIOUS, "--recent-days", "0")
        self.assertIn("MITRE ATT&CK techniques seen", out)
        self.assertIn("T1543.002", out)
        self.assertIn("T1053.006", out)

    def test_min_severity_filters_the_report(self):
        _code, out, _err = run_cli(SUSPICIOUS, "--recent-days", "0", "--min-severity", "high")
        self.assertIn("min severity : high", out)
        self.assertNotIn("timer_high_frequency", out)
        self.assertIn("exec_from_suspicious_path", out)

    def test_parse_warnings_are_surfaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "broken.service"), "w") as handle:
                handle.write("[Service]\nnot a directive\nExecStart=/tmp/x\n")
            _code, out, _err = run_cli(tmp, "--recent-days", "0")
            self.assertIn("Parse warnings", out)
            self.assertIn("broken.service", out)


class JsonOutputTests(unittest.TestCase):
    def test_json_is_valid_and_has_the_documented_shape(self):
        code, out, _err = run_cli(SUSPICIOUS, "--recent-days", "0", "--json")
        self.assertEqual(code, EXIT_FINDINGS)
        data = json.loads(out)
        self.assertEqual(data["tool"], "persistwatch")
        self.assertEqual(data["summary"]["units_parsed"], 7)
        self.assertGreater(data["summary"]["findings"], 0)
        self.assertIn("T1543.002", data["techniques"])
        for finding in data["findings"]:
            self.assertEqual(
                sorted(finding),
                ["evidence", "message", "path", "rule", "severity", "technique", "unit"],
            )

    def test_clean_json_has_an_empty_findings_list(self):
        code, out, _err = run_cli(CLEAN, "--recent-days", "0", "--json")
        self.assertEqual(code, EXIT_CLEAN)
        data = json.loads(out)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["summary"]["high"], 0)

    def test_json_counts_match_the_findings_list(self):
        _code, out, _err = run_cli(SUSPICIOUS, "--recent-days", "0", "--json")
        data = json.loads(out)
        self.assertEqual(data["summary"]["findings"], len(data["findings"]))
        self.assertEqual(
            data["summary"]["high"],
            len([f for f in data["findings"] if f["severity"] == "high"]),
        )


class OtherFlagTests(unittest.TestCase):
    def test_list_rules_prints_every_rule_and_exits_clean(self):
        code, out, _err = run_cli("--list-rules")
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("exec_from_suspicious_path", out)
        self.assertIn("timer_high_frequency", out)
        self.assertIn("T1543.002", out)

    def test_disable_removes_a_rule_from_the_report(self):
        _code, out, _err = run_cli(SUSPICIOUS, "--recent-days", "0", "--disable", "lookalike_name")
        self.assertNotIn("lookalike_name", out)

    def test_several_directories_can_be_scanned_at_once(self):
        _code, out, _err = run_cli(CLEAN, SUSPICIOUS, "--recent-days", "0")
        self.assertIn("units parsed : 11", out)

    def test_no_recursive_skips_subdirectories(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = os.path.join(tmp, "nested.d")
            os.mkdir(nested)
            with open(os.path.join(nested, "deep.service"), "w") as handle:
                handle.write("[Service]\nExecStart=/tmp/deep\n")
            _code, out, _err = run_cli(tmp, "--recent-days", "0")
            self.assertIn("units parsed : 1", out)
            _code, out, _err = run_cli(tmp, "--recent-days", "0", "--no-recursive")
            self.assertIn("units parsed : 0", out)

    def test_timer_threshold_flag_is_honoured(self):
        _code, out, _err = run_cli(
            SUSPICIOUS, "--recent-days", "0", "--timer-threshold", "1"
        )
        self.assertNotIn("timer_high_frequency", out)


if __name__ == "__main__":
    unittest.main()
