"""Tests for the systemd unit file parser."""

import os
import stat
import tempfile
import unittest

from tests.helpers import CLEAN, SUSPICIOUS

from persistwatch.parser import is_unit_filename, parse_file, parse_text, scan_directory


class ParseTextTests(unittest.TestCase):
    def test_repeated_keys_are_all_kept(self):
        unit = parse_text(
            "[Service]\nExecStartPre=/bin/one\nExecStartPre=/bin/two\n",
            path="/x/a.service",
        )
        self.assertEqual(unit.get("Service.ExecStartPre"), ["/bin/one", "/bin/two"])

    def test_line_continuation_is_folded(self):
        unit = parse_text(
            "[Service]\nExecStart=/bin/long \\\n  --flag \\\n  --other\n",
            path="/x/a.service",
        )
        self.assertEqual(unit.first("Service.ExecStart"), "/bin/long --flag --other")

    def test_both_comment_styles_are_ignored(self):
        unit = parse_text(
            "# hash comment\n; semicolon comment\n[Unit]\nDescription=real\n",
            path="/x/a.service",
        )
        self.assertEqual(unit.first("Unit.Description"), "real")
        self.assertEqual(len(unit.options), 1)

    def test_empty_value_resets_the_list(self):
        unit = parse_text(
            "[Service]\nExecStartPre=/bin/one\nExecStartPre=\n",
            path="/x/a.service",
        )
        self.assertEqual(unit.get("Service.ExecStartPre"), [])

    def test_keys_are_case_insensitive_but_casing_is_remembered(self):
        unit = parse_text("[Service]\nExecStart=/bin/true\n", path="/x/a.service")
        self.assertEqual(unit.first("service.execstart"), "/bin/true")
        self.assertEqual(unit.display("service.execstart"), "ExecStart")

    def test_key_outside_a_section_is_recorded_as_an_error(self):
        unit = parse_text("Description=orphan\n[Unit]\nDescription=real\n", path="/x/a.service")
        self.assertEqual(len(unit.parse_errors), 1)
        self.assertIn("outside any section", unit.parse_errors[0])
        self.assertEqual(unit.first("Unit.Description"), "real")

    def test_line_without_equals_is_recorded_as_an_error(self):
        unit = parse_text("[Unit]\nthis is not a directive\n", path="/x/a.service")
        self.assertEqual(len(unit.parse_errors), 1)
        self.assertIn("no '='", unit.parse_errors[0])

    def test_kind_comes_from_the_extension(self):
        self.assertEqual(parse_text("", path="/x/a.service").kind, "service")
        self.assertEqual(parse_text("", path="/x/a.timer").kind, "timer")
        self.assertEqual(parse_text("", path="/x/noext").kind, "unknown")

    def test_exec_lines_lists_every_exec_directive_with_file_casing(self):
        unit = parse_text(
            "[Service]\nExecStartPre=/bin/pre\nExecStart=/bin/main\nExecStop=/bin/stop\n"
            "[Unit]\nDescription=not an exec line\n",
            path="/x/a.service",
        )
        directives = [directive for directive, _ in unit.exec_lines()]
        self.assertEqual(sorted(directives), ["ExecStart", "ExecStartPre", "ExecStop"])


class FilenameTests(unittest.TestCase):
    def test_recognises_unit_extensions(self):
        for name in ("a.service", "a.timer", "a.socket", "a.path", "a.mount", "a.target"):
            self.assertTrue(is_unit_filename(name), name)

    def test_recognises_hidden_units(self):
        self.assertTrue(is_unit_filename(".sneaky.service"))

    def test_rejects_other_files(self):
        for name in ("README.md", "notes.txt", "service", "a.service.bak"):
            self.assertFalse(is_unit_filename(name), name)


class ParseFileTests(unittest.TestCase):
    def test_mode_and_mtime_are_recorded(self):
        unit = parse_file(os.path.join(CLEAN, "nginx.service"))
        self.assertTrue(unit.mode)
        self.assertGreater(unit.mtime, 0)
        self.assertEqual(unit.name, "nginx.service")

    def test_unreadable_bytes_do_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "binary.service")
            with open(path, "wb") as handle:
                handle.write(b"[Service]\nExecStart=/bin/true \xff\xfe\n")
            unit = parse_file(path)
            self.assertIn("/bin/true", unit.first("Service.ExecStart"))


class ScanDirectoryTests(unittest.TestCase):
    def test_finds_every_unit_in_the_fixture_directories(self):
        self.assertEqual(len(scan_directory(CLEAN)), 4)
        self.assertEqual(len(scan_directory(SUSPICIOUS)), 7)

    def test_results_are_sorted_by_path(self):
        paths = [unit.path for unit in scan_directory(SUSPICIOUS)]
        self.assertEqual(paths, sorted(paths))

    def test_skips_files_that_are_not_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "README.md"), "w").close()
            with open(os.path.join(tmp, "a.service"), "w") as handle:
                handle.write("[Service]\nExecStart=/bin/true\n")
            units = scan_directory(tmp)
            self.assertEqual([u.name for u in units], ["a.service"])

    def test_recursive_and_flat_scans_differ(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = os.path.join(tmp, "nested.d")
            os.mkdir(nested)
            for target in (tmp, nested):
                with open(os.path.join(target, "a.service"), "w") as handle:
                    handle.write("[Service]\nExecStart=/bin/true\n")
            self.assertEqual(len(scan_directory(tmp, recursive=True)), 2)
            self.assertEqual(len(scan_directory(tmp, recursive=False)), 1)

    def test_missing_directory_raises(self):
        with self.assertRaises(NotADirectoryError):
            scan_directory("/nonexistent/persistwatch/path")


if __name__ == "__main__":
    unittest.main()
