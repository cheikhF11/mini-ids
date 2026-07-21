"""Match dissected packets against loaded Snort-lite rules.

Signature rules without a ``threshold`` clause alert on every match (the
:class:`alerts.dispatcher.AlertDispatcher` cooldown handles anti-spam
upstream). Rules with a ``threshold`` clause keep their own per-rule sliding
window counter here, mirroring Snort's ``threshold``/``limit`` semantics.
"""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable

from core.models import Alert, PacketRecord
from rules.parser import parse_dir, parse_file
from rules.schema import DsizeSpec, Rule


def _ip_match(rule_ip: str, pkt_ip: str) -> bool:
    if rule_ip == "any":
        return True
    if not pkt_ip:
        return False
    try:
        if "/" in rule_ip:
            return ipaddress.ip_address(pkt_ip) in ipaddress.ip_network(rule_ip, strict=False)
    except ValueError:
        pass
    return rule_ip == pkt_ip


def _port_match(rule_port: str, pkt_port) -> bool:
    if rule_port == "any":
        return True
    if pkt_port is None:
        return False
    try:
        return int(rule_port) == int(pkt_port)
    except ValueError:
        return False


def _flags_match(rule_flags: str, pkt_flags: str) -> bool:
    if rule_flags == "":
        return True
    if rule_flags == "0":
        return pkt_flags == ""
    if rule_flags.startswith("="):
        return set(pkt_flags) == set(rule_flags[1:])
    return set(rule_flags).issubset(set(pkt_flags))


def _dsize_match(spec: DsizeSpec | None, payload_len: int) -> bool:
    if spec is None:
        return True
    if spec.op == ">":
        return payload_len > spec.value
    if spec.op == "<":
        return payload_len < spec.value
    return payload_len == spec.value


def _content_match(rule: Rule, payload: bytes) -> bool:
    if rule.content is None:
        return True
    if not payload:
        return False
    if rule.nocase:
        return rule.content.lower() in payload.lower()
    return rule.content in payload


def _header_match(rule: Rule, pkt: PacketRecord) -> bool:
    if rule.proto != "any" and rule.proto != pkt.proto.lower():
        return False
    return (
        _ip_match(rule.src_ip, pkt.src)
        and _ip_match(rule.dst_ip, pkt.dst)
        and _port_match(rule.src_port, pkt.sport)
        and _port_match(rule.dst_port, pkt.dport)
    )


class RuleMatcher:
    def __init__(self, rules: list[Rule], clock: Callable[[], float] = time.time):
        self.rules = rules
        self._clock = clock
        self._counters: dict[tuple, deque] = defaultdict(deque)
        self._last_fired: dict[tuple, float] = {}

    @classmethod
    def from_dir(cls, rules_dir: str | Path, clock: Callable[[], float] = time.time) -> "RuleMatcher":
        return cls(parse_dir(rules_dir), clock=clock)

    @classmethod
    def from_file(cls, path: str | Path, clock: Callable[[], float] = time.time) -> "RuleMatcher":
        return cls(parse_file(path), clock=clock)

    def _signature_matches(self, rule: Rule, pkt: PacketRecord) -> bool:
        return (
            _header_match(rule, pkt)
            and _flags_match(rule.flags, pkt.tcp_flags)
            and _dsize_match(rule.dsize, len(pkt.payload))
            and _content_match(rule, pkt.payload)
        )

    def _check_threshold(self, rule: Rule, pkt: PacketRecord, now: float) -> bool:
        spec = rule.threshold
        track_val = pkt.src if spec.track == "by_src" else pkt.dst
        key = (rule.sid, track_val)

        if spec.type == "limit":
            last = self._last_fired.get(key)
            if last is not None and now - last < spec.seconds:
                return False
            self._last_fired[key] = now
            return True

        window = self._counters[key]
        window.append(now)
        cutoff = now - spec.seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= spec.count:
            window.clear()
            return True
        return False

    def match(self, pkt: PacketRecord, now: float | None = None) -> list[Alert]:
        now = now if now is not None else self._clock()
        alerts = []
        for rule in self.rules:
            if not self._signature_matches(rule, pkt):
                continue
            if rule.threshold is not None and not self._check_threshold(rule, pkt, now):
                continue
            alerts.append(
                Alert(
                    kind="signature",
                    severity=rule.severity,
                    src=pkt.src,
                    dst=pkt.dst,
                    detail=rule.msg or rule.raw,
                    sid=rule.sid,
                    ts=now,
                )
            )
        return alerts
