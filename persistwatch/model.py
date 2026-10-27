"""Data types shared by the parser, the rules and the report."""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Unit:
    """One parsed systemd unit, timer, socket or path file.

    `options` maps "Section.Key" to every value seen for that key, because
    systemd allows a key to be repeated (ExecStartPre is the common case) and
    a rule that only looked at the last value would miss the others.
    """

    path: str
    name: str
    options: Dict[str, List[str]] = field(default_factory=dict)
    display_keys: Dict[str, str] = field(default_factory=dict)
    mode: int = 0
    mtime: float = 0.0
    parse_errors: List[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        """The unit type, taken from the file extension (service, timer, ...)."""
        _, _, ext = self.name.rpartition(".")
        return ext if ext and ext != self.name else "unknown"

    def get(self, key: str) -> List[str]:
        """Every value for "Section.Key", case-insensitively."""
        return self.options.get(key.lower(), [])

    def first(self, key: str) -> str:
        """The first value for "Section.Key", or an empty string."""
        values = self.get(key)
        return values[0] if values else ""

    def display(self, key: str) -> str:
        """The key as it was written in the file, for readable evidence lines."""
        lowered = key.lower()
        full = self.display_keys.get(lowered, lowered)
        return full.partition(".")[2] or full

    def exec_lines(self) -> List[Tuple[str, str]]:
        """Every Exec* directive as (directive, value) pairs, in file order.

        The directive keeps the casing used in the file, so evidence lines read
        like the unit rather than like an internal lookup key.
        """
        found = []
        for key, values in self.options.items():
            section, _, bare = key.partition(".")
            if section == "service" and bare.startswith("exec"):
                for value in values:
                    found.append((self.display(key), value))
        return found


@dataclass
class Finding:
    """One thing worth a second look, raised against one unit."""

    unit: str
    path: str
    rule: str
    severity: str
    technique: str
    message: str
    evidence: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {
            "unit": self.unit,
            "path": self.path,
            "rule": self.rule,
            "severity": self.severity,
            "technique": self.technique,
            "message": self.message,
            "evidence": self.evidence,
        }


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 0)
