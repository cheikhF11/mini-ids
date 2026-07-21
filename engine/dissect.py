"""Normalize a raw Scapy packet into a flat :class:`core.models.PacketRecord`.

Every field access is defensive (``try/except``) so a malformed or unusual
packet never aborts capture - worst case a field stays at its default.
"""

from __future__ import annotations

import time

from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.packet import Raw

from core.models import PacketRecord

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 10: "NULL"}


def _tcp_flags_str(flags) -> str:
    try:
        return str(flags)
    except Exception:
        return ""


def _layer_names(pkt: Packet) -> list[str]:
    names = []
    layer = pkt
    seen = 0
    while layer is not None and seen < 16:
        names.append(layer.__class__.__name__)
        layer = layer.payload if layer.payload and layer.payload.__class__.__name__ != "NoPayload" else None
        seen += 1
    return names


def _detect_http(payload: bytes) -> tuple[str, str]:
    method, host = "", ""
    try:
        if payload[:8].upper().startswith(_HTTP_METHODS) or any(payload.startswith(m) for m in _HTTP_METHODS):
            first_line = payload.split(b"\r\n", 1)[0]
            parts = first_line.split(b" ")
            if parts:
                method = parts[0].decode("ascii", errors="ignore")
        for line in payload.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("ascii", errors="ignore")
                break
    except Exception:
        pass
    return method, host


def dissect(pkt: Packet, no: int = 0, ts: float | None = None) -> PacketRecord:
    """Turn a raw Scapy packet into a :class:`PacketRecord`."""
    ts = ts if ts is not None else (float(getattr(pkt, "time", 0.0)) or time.time())
    rec = PacketRecord(no=no, ts=ts, length=len(pkt), layers=_layer_names(pkt))

    try:
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            rec.src_mac, rec.dst_mac = eth.src, eth.dst
    except Exception:
        pass

    try:
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            rec.proto = "ARP"
            rec.arp_op = int(arp.op)
            rec.arp_psrc = str(arp.psrc)
            rec.arp_hwsrc = str(arp.hwsrc)
            rec.src, rec.dst = str(arp.psrc), str(arp.pdst)
            rec.info = f"ARP {'who-has' if arp.op == 1 else 'is-at'} {arp.pdst}"
            return rec
    except Exception:
        pass

    try:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            rec.src, rec.dst = str(ip.src), str(ip.dst)
            rec.proto = "IPv4"
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            rec.src, rec.dst = str(ip6.src), str(ip6.dst)
            rec.proto = "IPv6"
    except Exception:
        pass

    try:
        if pkt.haslayer(ICMP):
            rec.proto = "ICMP"
            rec.info = f"ICMP type={pkt[ICMP].type} code={pkt[ICMP].code}"
    except Exception:
        pass

    try:
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            rec.proto = "TCP"
            rec.sport, rec.dport = int(tcp.sport), int(tcp.dport)
            rec.tcp_flags = _tcp_flags_str(tcp.flags)
            rec.info = f"TCP {rec.sport}->{rec.dport} [{rec.tcp_flags}]"
    except Exception:
        pass

    try:
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            rec.proto = "UDP"
            rec.sport, rec.dport = int(udp.sport), int(udp.dport)
            rec.info = f"UDP {rec.sport}->{rec.dport}"
    except Exception:
        pass

    try:
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            rec.proto = "DNS"
            rec.dns_qr = int(dns.qr)
            question = dns.qd[0] if dns.qd else None
            if question is not None:
                qname = question.qname
                rec.dns_qname = qname.decode("ascii", errors="ignore").rstrip(".") if isinstance(qname, bytes) else str(qname).rstrip(".")
                rec.dns_qtype = _QTYPES.get(int(question.qtype), str(question.qtype))
            rec.info = f"DNS {'response' if rec.dns_qr else 'query'} {rec.dns_qname}"
    except Exception:
        pass

    try:
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            rec.payload = payload
            method, host = _detect_http(payload)
            if method:
                rec.proto = "HTTP"
                rec.http_method = method
                rec.http_host = host
                rec.info = f"HTTP {method} {host}"
    except Exception:
        pass

    if not rec.info:
        rec.info = rec.proto

    return rec
