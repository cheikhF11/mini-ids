"""Lab-only repeated-connection-attempt generator, used to exercise mini-ids's
own ``detectors.brute_force.BruteForceDetector`` and the brute-force
threshold rules.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from offensive.guard import require_lab_target


def build_attempt_packets(target_ip: str, port: int, attempts: int, src_port_start: int = 50000) -> list[Packet]:
    return [IP(dst=target_ip) / TCP(sport=src_port_start + i, dport=port, flags="S") for i in range(attempts)]


def simulate(
    target_ip: str,
    port: int = 22,
    attempts: int = 8,
    override: bool = False,
    send_fn: Optional[Callable[[Packet], None]] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    delay: float = 0.5,
) -> int:
    """Send ``attempts`` fresh SYN connection attempts to ``target_ip:port``.

    Refuses non-lab targets unless ``override`` is set (``--i-understand-lab``).
    """
    require_lab_target(target_ip, override=override)

    if send_fn is None:
        from scapy.sendrecv import send as scapy_send

        send_fn = lambda pkt: scapy_send(pkt, verbose=False)

    count = 0
    for pkt in build_attempt_packets(target_ip, port, attempts):
        send_fn(pkt)
        count += 1
        if delay:
            sleep_fn(delay)
    return count
