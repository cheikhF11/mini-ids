"""Parser for a practical subset of real Snort rule syntax.

Grammar::

    action proto src_ip src_port -> dst_ip dst_port (option:value; option2:value2; ...)

Example::

    alert tcp any any -> any 22 (msg:"SSH brute-force"; flags:S; \
        threshold: type threshold, track by_src, count 5, seconds 60; sid:1000001; severity:medium;)

Supported options: ``msg``, ``sid``, ``rev``, ``classtype``, ``content``
(+ ``nocase``), ``flags``, ``dsize``, ``threshold``, ``severity`` (a custom
extension - real Snort has no severity keyword, but it is directly useful for
alert routing here).
"""

from __future__ import annotations

import re
from pathlib import Path

from rules.schema import DsizeSpec, Rule, ThresholdSpec

_HEADER_RE = re.compile(
    r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s*->\s*"
    r"(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s*\((?P<options>.*)\)\s*$"
)


class RuleParseError(ValueError):
    pass


def _split_options(options: str) -> list[str]:
    """Split the options block on ';', respecting quoted strings."""
    parts, current, in_quotes = [], [], False
    for ch in options:
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == ";" and not in_quotes:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _parse_threshold(value: str) -> ThresholdSpec:
    spec = ThresholdSpec()
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        tokens = chunk.split()
        if len(tokens) < 2:
            continue
        key, val = tokens[0], tokens[1]
        if key == "type":
            spec.type = val
        elif key == "track":
            spec.track = val
        elif key == "count":
            spec.count = int(val)
        elif key == "seconds":
            spec.seconds = float(val)
    return spec


def _parse_dsize(value: str) -> DsizeSpec:
    value = value.strip()
    op = value[0] if value[0] in "><=" else "="
    number = value[1:] if value[0] in "><=" else value
    return DsizeSpec(op=op, value=int(number))


def parse_rule(line: str) -> Rule | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    match = _HEADER_RE.match(line)
    if not match:
        raise RuleParseError(f"malformed rule header: {line!r}")
    g = match.groupdict()
    rule = Rule(
        sid=0,
        action=g["action"],
        proto=g["proto"].lower(),
        src_ip=g["src_ip"],
        src_port=g["src_port"],
        dst_ip=g["dst_ip"],
        dst_port=g["dst_port"],
        raw=line,
    )

    for opt in _split_options(g["options"]):
        if ":" in opt:
            key, _, value = opt.partition(":")
        else:
            key, value = opt, ""
        key = key.strip().lower()
        value = value.strip()

        if key == "msg":
            rule.msg = _unquote(value)
        elif key == "sid":
            rule.sid = int(value)
        elif key == "rev":
            rule.rev = int(value)
        elif key == "classtype":
            rule.classtype = _unquote(value)
        elif key == "content":
            content = _unquote(value)
            rule.content = content.encode("latin-1")
        elif key == "nocase":
            rule.nocase = True
        elif key == "flags":
            rule.flags = value.strip()
        elif key == "dsize":
            rule.dsize = _parse_dsize(value)
        elif key == "threshold":
            rule.threshold = _parse_threshold(value)
        elif key == "severity":
            rule.severity = value.strip().lower()
        # unknown options are ignored - forward-compatible with real Snort keywords we don't act on

    if rule.sid == 0:
        raise RuleParseError(f"rule missing required sid: {line!r}")
    return rule


def parse_file(path: str | Path) -> list[Rule]:
    rules = []
    for line in Path(path).read_text().splitlines():
        rule = parse_rule(line)
        if rule is not None:
            rules.append(rule)
    return rules


def parse_dir(dir_path: str | Path) -> list[Rule]:
    rules = []
    for path in sorted(Path(dir_path).glob("*.rules")):
        rules.extend(parse_file(path))
    return rules
