"""Shared Scapy packet builders for tests.

Explicit Ether MACs avoid Scapy's ARP-resolution warnings that show up when
building ``Ether()/IP()`` without a real routing table (harmless, just noisy).
"""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

_SRC_MAC = "aa:bb:cc:dd:ee:01"
_DST_MAC = "aa:bb:cc:dd:ee:02"


def eth() -> Ether:
    return Ether(src=_SRC_MAC, dst=_DST_MAC)


def tcp_packet(src: str, dst: str, sport: int, dport: int, flags: str = "S", payload: bytes = b"") -> Packet:
    pkt = eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def udp_packet(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> Packet:
    pkt = eth() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def dns_query_packet(src: str, dst: str, qname: str, qtype: int = 1, sport: int = 53000) -> Packet:
    return eth() / IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(qr=0, qd=DNSQR(qname=qname, qtype=qtype))


def arp_packet(psrc: str, pdst: str, hwsrc: str = _SRC_MAC, op: int = 1) -> Packet:
    return eth() / ARP(op=op, psrc=psrc, pdst=pdst, hwsrc=hwsrc)
