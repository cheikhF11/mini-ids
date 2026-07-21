"""Data shapes for the Snort-lite rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ThresholdSpec:
    """``threshold: type threshold, track by_src, count 5, seconds 60``"""

    type: str = "threshold"  # "threshold" (fire+reset) or "limit" (fire once per window)
    track: str = "by_src"  # "by_src" or "by_dst"
    count: int = 1
    seconds: float = 60.0


@dataclass
class DsizeSpec:
    op: str  # ">" | "<" | "="
    value: int


@dataclass
class Rule:
    sid: int
    msg: str = ""
    action: str = "alert"
    proto: str = "any"  # tcp | udp | icmp | any
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    flags: str = ""  # "" = don't care, "0" = no flags, "=XYZ" = exact set, "XYZ" = at-least
    content: Optional[bytes] = None
    nocase: bool = False
    dsize: Optional[DsizeSpec] = None
    threshold: Optional[ThresholdSpec] = None
    severity: str = "medium"
    rev: int = 1
    classtype: str = ""
    raw: str = field(default="", repr=False)
