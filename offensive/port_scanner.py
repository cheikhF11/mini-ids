"""Lab-only SYN port-scan traffic generator, used to exercise mini-ids's own
``detectors.port_scan.PortScanDetector`` and the port-scan signature rules.
"""

from __future__ import annotations

import time
from typing import Callable, Iterable, Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from offensive.guard import require_lab_target

DEFAULT_PORTS = list(range(20, 1044))


def build_syn_packets(target_ip: str, ports: Iterable[int], src_port: int = 40000) -> list[Packet]:
    return [IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S") for port in ports]


def scan(
    target_ip: str,
    ports: Optional[list[int]] = None,
    override: bool = False,
    send_fn: Optional[Callable[[Packet], None]] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    delay: float = 0.02,
) -> int:
    """Send a SYN packet to each port in ``ports`` against ``target_ip``.

    ``send_fn`` defaults to Scapy's ``send()`` and is injectable for tests.
    Refuses non-lab targets unless ``override`` is set (``--i-understand-lab``).
    """
    require_lab_target(target_ip, override=override)
    ports = ports if ports is not None else DEFAULT_PORTS

    if send_fn is None:
        from scapy.sendrecv import send as scapy_send

        send_fn = lambda pkt: scapy_send(pkt, verbose=False)

    count = 0
    for pkt in build_syn_packets(target_ip, ports):
        send_fn(pkt)
        count += 1
        if delay:
            sleep_fn(delay)
    return count
