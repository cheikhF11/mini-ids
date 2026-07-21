"""Packet sources: live interface capture and offline pcap read/replay.

Both paths funnel into the same ``prn`` callback signature so a live NIC and a
recorded pcap are interchangeable inputs to the pipeline - live capture needs
root/CAP_NET_RAW and a real interface, pcap replay does not, which is what
keeps the whole detection stack unit-testable offline.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from scapy.packet import Packet


def list_interfaces() -> list[str]:
    from scapy.arch import get_if_list

    return list(get_if_list())


class LiveCapture:
    """Non-blocking live capture backed by Scapy's :class:`AsyncSniffer`."""

    def __init__(self, prn: Callable[[Packet], None], iface: Optional[str] = None, bpf_filter: Optional[str] = None):
        self.prn = prn
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._sniffer = None

    def start(self) -> None:
        from scapy.sendrecv import AsyncSniffer

        self._sniffer = AsyncSniffer(prn=self.prn, iface=self.iface, filter=self.bpf_filter, store=False)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None


def read_pcap(path: str, prn: Callable[[Packet], None], count: Optional[int] = None) -> int:
    """Stream every packet in a pcap file through ``prn``. Returns the count read."""
    from scapy.utils import PcapReader

    n = 0
    with PcapReader(path) as reader:
        for pkt in reader:
            prn(pkt)
            n += 1
            if count is not None and n >= count:
                break
    return n


def replay_pcap(
    path: str,
    prn: Callable[[Packet], None],
    speed: float = 1.0,
    max_gap: float = 1.0,
    sleep_fn: Callable[[float], None] = time.sleep,
    stop_flag: Optional[Callable[[], bool]] = None,
) -> int:
    """Replay a pcap reproducing inter-packet timing, capped by ``max_gap``."""
    from scapy.utils import PcapReader

    n = 0
    last_ts: Optional[float] = None
    with PcapReader(path) as reader:
        for pkt in reader:
            if stop_flag is not None and stop_flag():
                break
            ts = float(getattr(pkt, "time", 0.0))
            if last_ts is not None and speed > 0:
                gap = min(max(ts - last_ts, 0.0), max_gap) / speed
                if gap > 0:
                    sleep_fn(gap)
            last_ts = ts
            prn(pkt)
            n += 1
    return n
