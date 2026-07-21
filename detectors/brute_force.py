"""Behavioral brute-force detector: repeated connection attempts (SYNs
without an ACK) to a sensitive port from one source, within a sliding window.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable, Optional

from core.config import BruteForceConfig
from core.models import Alert, PacketRecord


class BruteForceDetector:
    def __init__(self, config: Optional[BruteForceConfig] = None, clock: Callable[[], float] = time.time):
        self.cfg = config or BruteForceConfig()
        self._clock = clock
        self._events: dict[tuple, deque] = defaultdict(deque)
        self._last_alert: dict[tuple, float] = {}

    def observe(self, pkt: PacketRecord, now: Optional[float] = None) -> Optional[Alert]:
        if pkt.proto != "TCP" or pkt.dport not in self.cfg.ports:
            return None
        if "S" not in pkt.tcp_flags or "A" in pkt.tcp_flags:
            return None  # only count fresh connection attempts, not established traffic
        now = now if now is not None else self._clock()

        key = (pkt.src, pkt.dst, pkt.dport)
        events = self._events[key]
        events.append(now)
        cutoff = now - self.cfg.window_seconds
        while events and events[0] < cutoff:
            events.popleft()

        if len(events) < self.cfg.attempt_threshold:
            return None

        last = self._last_alert.get(key)
        if last is not None and now - last < self.cfg.cooldown:
            return None
        self._last_alert[key] = now

        detail = f"{len(events)} connection attempts to {pkt.dst}:{pkt.dport} from {pkt.src} in {self.cfg.window_seconds:.0f}s"
        return Alert(kind="brute_force", severity="medium", src=pkt.src, dst=pkt.dst, detail=detail, ts=now, score=float(len(events)))
