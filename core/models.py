"""Canonical data-shape contracts shared by every module in the pipeline.

Every producer/consumer in the engine (capture -> dissect -> flows -> rules ->
detectors -> alerts -> storage -> dashboard) speaks in these dataclasses. Each
has a ``to_dict()`` so the same object can be JSON-serialized for the SQLite
store, the JSONL alert log, and the Socket.IO dashboard feed without a second
shape existing anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class PacketRecord:
    """One dissected packet, defensively normalized from a raw Scapy frame."""

    no: int
    ts: float
    length: int
    layers: list[str] = field(default_factory=list)
    proto: str = "unknown"
    info: str = ""

    src: str = ""
    dst: str = ""
    src_mac: str = ""
    dst_mac: str = ""

    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: str = ""

    arp_op: Optional[int] = None
    arp_psrc: str = ""
    arp_hwsrc: str = ""

    dns_qr: Optional[int] = None
    dns_qname: str = ""
    dns_qtype: str = ""

    http_method: str = ""
    http_host: str = ""

    payload: bytes = b""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["payload"] = self.payload.decode("latin-1") if self.payload else ""
        return d


@dataclass
class Flow:
    """Stateful 5-tuple aggregation, updated as packets arrive."""

    proto: str
    src: str
    sport: Optional[int]
    dst: str
    dport: Optional[int]

    packet_count: int = 0
    byte_count: int = 0
    start_ts: float = 0.0
    last_ts: float = 0.0
    flags_seen: set[str] = field(default_factory=set)
    syn_count: int = 0

    @property
    def key(self) -> tuple:
        return (self.proto, self.src, self.sport, self.dst, self.dport)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.start_ts)

    @property
    def avg_packet_size(self) -> float:
        return self.byte_count / self.packet_count if self.packet_count else 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["flags_seen"] = sorted(self.flags_seen)
        d["duration"] = self.duration
        d["avg_packet_size"] = self.avg_packet_size
        return d


@dataclass
class Alert:
    """A deduplicated, emittable alert produced by a rule or detector."""

    kind: str
    severity: str
    src: str
    detail: str
    ts: float
    dst: str = ""
    sid: Optional[int] = None
    score: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)
