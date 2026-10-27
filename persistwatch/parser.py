"""Read systemd unit files.

systemd's format looks like INI but is not quite INI: a key may appear more
than once and the repeats all count, a trailing backslash continues the line,
and comments start with either "#" or ";". configparser gets the repeats
wrong, so this module does the small amount of work by hand.
"""

import os
from typing import Iterable, List, Optional

from .model import Unit

UNIT_SUFFIXES = (
    ".service",
    ".timer",
    ".socket",
    ".path",
    ".mount",
    ".target",
)


def _join_continuations(lines: Iterable[str]) -> List[str]:
    """Fold "ExecStart=/bin/a \\\\\\n  --flag" back into one logical line."""
    joined: List[str] = []
    buffer: Optional[str] = None
    for raw in lines:
        line = raw.rstrip("\n").rstrip("\r")
        if buffer is not None:
            line = buffer + " " + line.strip()
            buffer = None
        if line.rstrip().endswith("\\"):
            buffer = line.rstrip()[:-1].rstrip()
            continue
        joined.append(line)
    if buffer is not None:
        joined.append(buffer)
    return joined


def parse_text(text: str, path: str = "<string>", name: str = "") -> Unit:
    """Parse unit file contents into a Unit."""
    unit = Unit(path=path, name=name or os.path.basename(path))
    section = ""
    section_display = ""
    for number, line in enumerate(_join_continuations(text.splitlines()), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section_display = stripped[1:-1].strip()
            section = section_display.lower()
            continue
        if "=" not in stripped:
            unit.parse_errors.append("line %d: no '=' and not a section header" % number)
            continue
        key, _, value = stripped.partition("=")
        original_key = key.strip()
        key = original_key.lower()
        value = value.strip()
        if not key:
            unit.parse_errors.append("line %d: empty key" % number)
            continue
        if not section:
            unit.parse_errors.append("line %d: key outside any section" % number)
            continue
        full = "%s.%s" % (section, key)
        unit.display_keys.setdefault(full, "%s.%s" % (section_display, original_key))
        if value == "":
            # An empty assignment resets the list in systemd, so honour that.
            unit.options[full] = []
            continue
        unit.options.setdefault(full, []).append(value)
    return unit


def parse_file(path: str) -> Unit:
    """Parse one unit file from disk, recording its mode and mtime."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    unit = parse_text(text, path=path, name=os.path.basename(path))
    try:
        info = os.stat(path)
        unit.mode = info.st_mode
        unit.mtime = info.st_mtime
    except OSError as exc:
        unit.parse_errors.append("stat failed: %s" % exc)
    return unit


def is_unit_filename(name: str) -> bool:
    base = name.lstrip(".")
    return base.endswith(UNIT_SUFFIXES)


def scan_directory(directory: str, recursive: bool = True) -> List[Unit]:
    """Parse every unit file under `directory`, sorted by path for stable output."""
    units: List[Unit] = []
    if not os.path.isdir(directory):
        raise NotADirectoryError("not a directory: %s" % directory)
    if recursive:
        walker = os.walk(directory)
    else:
        walker = [(directory, [], sorted(os.listdir(directory)))]
    for root, _dirs, files in walker:
        for filename in sorted(files):
            if not is_unit_filename(filename):
                continue
            full = os.path.join(root, filename)
            if not os.path.isfile(full):
                continue
            units.append(parse_file(full))
    units.sort(key=lambda u: u.path)
    return units
