"""Stateful 5-tuple flow aggregation, with idle expiry.

Feeds the ML anomaly detector (per-flow numeric features) and gives
port-scan/brute-force detectors a normalized view of "connections" instead of
raw packets.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from core.models import Flow, PacketRecord


class FlowTable:
    def __init__(
        self,
        idle_timeout: float = 120.0,
        clock: Callable[[], float] = time.time,
        on_evict: Optional[Callable[[Flow], None]] = None,
    ):
        self.idle_timeout = idle_timeout
        self._clock = clock
        self._on_evict = on_evict
        self._flows: dict[tuple, Flow] = {}

    def update(self, pkt: PacketRecord) -> Optional[Flow]:
        """Update (or create) the flow this packet belongs to. Returns it."""
        if not pkt.src or not pkt.dst:
            return None
        key = (pkt.proto, pkt.src, pkt.sport, pkt.dst, pkt.dport)
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(proto=pkt.proto, src=pkt.src, sport=pkt.sport, dst=pkt.dst, dport=pkt.dport, start_ts=pkt.ts)
            self._flows[key] = flow
        flow.packet_count += 1
        flow.byte_count += pkt.length
        flow.last_ts = pkt.ts
        if pkt.tcp_flags:
            flow.flags_seen.add(pkt.tcp_flags)
            if "S" in pkt.tcp_flags and "A" not in pkt.tcp_flags:
                flow.syn_count += 1
        self._expire(pkt.ts)
        return flow

    def _expire(self, now: float) -> None:
        cutoff = now - self.idle_timeout
        stale = [k for k, f in self._flows.items() if f.last_ts < cutoff]
        for k in stale:
            flow = self._flows.pop(k)
            if self._on_evict is not None:
                self._on_evict(flow)

    def all(self) -> list[Flow]:
        return list(self._flows.values())

    def __len__(self) -> int:
        return len(self._flows)
