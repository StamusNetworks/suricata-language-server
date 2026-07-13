"""
Copyright(C) 2026 Stamus Networks SAS
Written by Eric Leblond <el@stamus-networks.com>

This file is part of Suricata Language Server.

Suricata Language Server is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Suricata Language Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Suricata Language Server.  If not, see <http://www.gnu.org/licenses/>.
"""

import re

RULE_START = re.compile(
    r"^\s*(?:#\s*)?(alert|drop|reject|pass|log|rejectsrc|rejectdst|rejectboth)\b"
)


def iter_rules(text, include_disabled=False):
    """Yield full rule strings from a rules file body, joining backslash-continued lines.

    Args:
        text: raw rules file content
        include_disabled: also yield commented-out rules (leading '#')

    Yields:
        str: one signature per iteration
    """
    if include_disabled:
        rule_start = re.compile(
            r"^\s*#?\s*(alert|drop|reject|pass|log|rejectsrc|rejectdst|rejectboth)\b"
        )
    else:
        rule_start = RULE_START

    buf = []
    for line in text.splitlines():
        if buf:
            buf.append(line.rstrip("\\").strip())
            if not line.rstrip().endswith("\\"):
                yield " ".join(buf)
                buf = []
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if not include_disabled and stripped.startswith("#"):
            continue
        if not rule_start.match(line):
            continue
        if line.rstrip().endswith("\\"):
            buf.append(line.rstrip("\\").strip())
        else:
            yield stripped


def extract_options(rule):
    """Return the option block between the outermost parentheses."""
    start = rule.find("(")
    end = rule.rfind(")")
    if start == -1 or end == -1 or end <= start:
        return None
    return rule[start + 1 : end]


def split_options(options):
    """Split an options string on ';' while respecting quoted strings."""
    parts = []
    current = []
    in_quote = False
    escape = False
    for ch in options:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\":
            current.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            continue
        if ch == ";" and not in_quote:
            token = "".join(current).strip()
            if token:
                parts.append(token)
            current = []
            continue
        current.append(ch)
    token = "".join(current).strip()
    if token:
        parts.append(token)
    return parts


def parse_metadata_value(value):
    """Turn 'k1 v1, k2 v2, k2 v3' into {'k1': ['v1'], 'k2': ['v2', 'v3']}."""
    result = {}
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        key, _, val = item.partition(" ")
        result.setdefault(key.strip(), []).append(val.strip())
    return result


def strip_quotes(value):
    """Remove surrounding double quotes from a token value."""
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_rule(rule):
    """Parse a single signature into {'sid', 'msg', 'metadata', 'options', 'header'}.

    Returns None if the rule has no SID (parser cannot key it).
    """
    options = extract_options(rule)
    if options is None:
        return None
    header = rule[: rule.find("(")].strip()
    entry = {
        "sid": None,
        "msg": None,
        "metadata": {},
        "options": {},
        "header": header,
    }
    for token in split_options(options):
        key, sep, val = token.partition(":")
        if not sep:
            key = key.strip()
            if key:
                entry["options"].setdefault(key, []).append("")
            continue
        key = key.strip()
        val = val.strip()
        if key == "sid":
            try:
                entry["sid"] = int(val)
            except ValueError:
                entry["sid"] = val
        elif key == "msg":
            entry["msg"] = strip_quotes(val)
        elif key == "metadata":
            entry["metadata"] = parse_metadata_value(val)
        else:
            entry["options"].setdefault(key, []).append(val)
    if entry["sid"] is None:
        return None
    return entry


def parse_rules_file(text, include_disabled=False):
    """Parse all rules in a text buffer and return a list of parsed rules."""
    parsed = []
    for rule in iter_rules(text, include_disabled=include_disabled):
        entry = parse_rule(rule)
        if entry is not None:
            parsed.append(entry)
    return parsed
