"""Shared paths and helpers for the test suite."""

import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
FIXTURES = os.path.join(TESTS_DIR, "fixtures")
CLEAN = os.path.join(FIXTURES, "clean")
SUSPICIOUS = os.path.join(FIXTURES, "suspicious")

if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def rules_fired(findings, unit_name=None):
    """The set of rule names in `findings`, optionally for one unit only."""
    return {
        f.rule
        for f in findings
        if unit_name is None or f.unit == unit_name
    }


def findings_for(findings, rule):
    return [f for f in findings if f.rule == rule]
