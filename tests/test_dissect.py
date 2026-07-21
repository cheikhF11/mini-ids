from engine.dissect import dissect
from tests.helpers import arp_packet, dns_query_packet, tcp_packet, udp_packet


def test_dissect_tcp():
    pkt = tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, flags="S")
    rec = dissect(pkt, no=1)
    assert rec.proto == "TCP"
    assert rec.src == "10.0.0.1"
    assert rec.dst == "10.0.0.2"
    assert rec.sport == 1234
    assert rec.dport == 80
    assert rec.tcp_flags == "S"


def test_dissect_udp():
    pkt = udp_packet("10.0.0.1", "10.0.0.2", 5000, 53)
    rec = dissect(pkt, no=1)
    assert rec.proto == "UDP"
    assert rec.sport == 5000
    assert rec.dport == 53


def test_dissect_dns_query():
    pkt = dns_query_packet("10.0.0.5", "10.0.0.53", "example.org")
    rec = dissect(pkt, no=1)
    assert rec.proto == "DNS"
    assert rec.dns_qr == 0
    assert rec.dns_qname == "example.org"
    assert rec.dns_qtype == "A"


def test_dissect_arp():
    pkt = arp_packet("10.0.0.2", "10.0.0.1")
    rec = dissect(pkt, no=1)
    assert rec.proto == "ARP"
    assert rec.arp_op == 1
    assert rec.src == "10.0.0.2"
    assert rec.dst == "10.0.0.1"


def test_dissect_http_basic_auth():
    payload = b"GET /secret HTTP/1.1\r\nHost: example.org\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
    pkt = tcp_packet("10.0.0.5", "10.0.0.1", 40000, 80, flags="PA", payload=payload)
    rec = dissect(pkt, no=1)
    assert rec.proto == "HTTP"
    assert rec.http_method == "GET"
    assert rec.http_host == "example.org"
    assert b"Authorization: Basic" in rec.payload


def test_dissect_null_scan_has_no_flags():
    pkt = tcp_packet("10.0.0.9", "10.0.0.1", 12345, 443, flags="")
    rec = dissect(pkt, no=1)
    assert rec.tcp_flags == ""


def test_dissect_malformed_never_raises():
    # A bare Ether frame with no IP/TCP/UDP layer - every branch must no-op safely.
    pkt = tcp_packet("10.0.0.1", "10.0.0.2", 1, 2)
    pkt = pkt.__class__(bytes(pkt)[:14])  # truncate to just the Ethernet header
    rec = dissect(pkt, no=1)
    assert rec.length >= 0
