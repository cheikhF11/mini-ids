"""Behavioral port-scan detector: distinct destination ports per source host
within a sliding window, with basic scan-type classification from TCP flags.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict, deque
from typing import Callable, Optional

from core.config import PortScanConfig
from core.models import Alert, PacketRecord

_SCAN_SIGNATURES = {
    frozenset("FPU"): "XMAS",
    frozenset("F"): "FIN",
    frozenset("S"): "SYN",
    frozenset("A"): "ACK",
}


def _classify(flags_list: list[str]) -> str:
    counts = Counter(f for f in flags_list if f)
    if not counts:
        return "NULL"
    most_common_flags, _ = counts.most_common(1)[0]
    return _SCAN_SIGNATURES.get(frozenset(most_common_flags), "TCP")


class PortScanDetector:
    def __init__(self, config: Optional[PortScanConfig] = None, clock: Callable[[], float] = time.time):
        self.cfg = config or PortScanConfig()
        self._clock = clock
        self._events: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}

    def observe(self, pkt: PacketRecord, now: Optional[float] = None) -> Optional[Alert]:
        if pkt.proto not in ("TCP", "UDP") or pkt.dport is None or not pkt.src:
            return None
        now = now if now is not None else self._clock()

        events = self._events[pkt.src]
        events.append((now, pkt.dport, pkt.tcp_flags))
        cutoff = now - self.cfg.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()

        distinct_ports = {e[1] for e in events}
        if len(distinct_ports) < self.cfg.port_threshold:
            return None

        last = self._last_alert.get(pkt.src)
        if last is not None and now - last < self.cfg.cooldown:
            return None
        self._last_alert[pkt.src] = now

        scan_type = _classify([e[2] for e in events])
        detail = f"{scan_type} scan: {len(distinct_ports)} distinct ports from {pkt.src} in {self.cfg.window_seconds:.0f}s"
        return Alert(kind="port_scan", severity="high", src=pkt.src, dst="", detail=detail, ts=now, score=float(len(distinct_ports)))
