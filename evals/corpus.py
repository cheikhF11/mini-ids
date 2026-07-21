"""Seeded synthetic corpora for the detection-accuracy eval.

Each generator returns a list of ``(ts, PacketRecord)`` events in time order,
plus a ``labels`` dict mapping a "case key" (the source IP for port-scan /
brute-force, the registered domain for exfil) to a ground-truth
``malicious: bool``. Every corpus deliberately includes benign look-alikes
and adversarial edge cases (a slow scan below threshold, a legitimate
multi-connection client, a benign long-but-real hostname) so the precision/
recall gate is meaningful rather than tautological.
"""

from __future__ import annotations

import random
from dataclasses import replace

from core.models import Flow, PacketRecord

_BASE = PacketRecord(no=0, ts=0.0, length=60)


def _pkt(**kwargs) -> PacketRecord:
    return replace(_BASE, **kwargs)


def generate_port_scan_cases(seed: int = 1337, n_scanners: int = 12, n_benign: int = 40):
    rng = random.Random(seed)
    events: list[tuple[float, PacketRecord]] = []
    labels: dict[str, bool] = {}
    t = 0.0

    # Malicious: fast scanners hitting many distinct ports well inside the window.
    for i in range(n_scanners):
        src = f"10.50.{i // 250}.{i % 250 + 1}"
        dst = "10.0.0.1"
        labels[src] = True
        ports = rng.sample(range(1, 65535), k=rng.randint(20, 45))
        for j, port in enumerate(ports):
            ts = t + j * 0.05
            events.append((ts, _pkt(proto="TCP", src=src, dst=dst, sport=50000 + j, dport=port, tcp_flags="S", ts=ts)))
        t += 3.0

    # Benign: a real multi-service client, a handful of ports spread over minutes (below threshold, slow).
    for i in range(n_benign):
        src = f"192.168.1.{i % 250 + 1}"
        dst = "93.184.216.34"
        labels[src] = False
        for j, port in enumerate([80, 443, 8443]):
            ts = t + j * 4.0
            events.append((ts, _pkt(proto="TCP", src=src, dst=dst, sport=51000 + j, dport=port, tcp_flags="S", ts=ts)))
        t += 1.0

    # Adversarial: a slow scan that stays *below* the port-count threshold - must NOT trigger.
    slow_src = "172.16.5.5"
    labels[slow_src] = False
    for j, port in enumerate(rng.sample(range(1, 65535), k=8)):
        ts = t + j * 0.2
        events.append((ts, _pkt(proto="TCP", src=slow_src, dst="172.16.5.1", sport=52000 + j, dport=port, tcp_flags="S", ts=ts)))

    events.sort(key=lambda e: e[0])
    return events, labels


def generate_brute_force_cases(seed: int = 1337, n_attackers: int = 10, n_benign: int = 40):
    rng = random.Random(seed + 1)
    events: list[tuple[float, PacketRecord]] = []
    labels: dict[str, bool] = {}
    t = 0.0

    # Malicious: repeated SSH connection attempts to one host, well inside the window.
    for i in range(n_attackers):
        src = f"10.60.{i // 250}.{i % 250 + 1}"
        dst = "10.0.0.22"
        labels[src] = True
        attempts = rng.randint(6, 12)
        for j in range(attempts):
            ts = t + j * 2.0
            events.append((ts, _pkt(proto="TCP", src=src, dst=dst, sport=53000 + j, dport=22, tcp_flags="S", ts=ts)))
        t += 3.0

    # Benign: a couple of legitimate retries (below threshold) plus an established session (SA, never counted).
    for i in range(n_benign):
        src = f"192.168.2.{i % 250 + 1}"
        dst = "10.0.0.22"
        labels[src] = False
        for j in range(2):  # 2 retries, well below the threshold of 5
            ts = t + j * 2.0
            events.append((ts, _pkt(proto="TCP", src=src, dst=dst, sport=54000 + j, dport=22, tcp_flags="S", ts=ts)))
        ts = t + 10.0
        events.append((ts, _pkt(proto="TCP", src=src, dst=dst, sport=54100, dport=22, tcp_flags="SA", ts=ts)))
        t += 1.0

    events.sort(key=lambda e: e[0])
    return events, labels


def _random_label(rng: random.Random, length: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _encoded_label(rng: random.Random, length: int) -> str:
    alphabet = "abcdefghijklmnop234567"  # base32-ish alphabet -> high entropy
    return "".join(rng.choice(alphabet) for _ in range(length))


def generate_exfil_cases(seed: int = 1337, n_tunnels: int = 6, per_tunnel: int = 40, n_benign_domains: int = 80):
    rng = random.Random(seed + 2)
    events: list[tuple[float, PacketRecord]] = []
    labels: dict[str, bool] = {}
    t = 0.0

    # Malicious: DNS tunneling - long high-entropy encoded labels fanned out under one domain.
    # Each tunnel's registered domain (last two labels) must be unique so cases don't collide.
    for i in range(n_tunnels):
        domain = f"tunnel{i}-evil-lab.test"
        labels[domain] = True
        for j in range(per_tunnel):
            ts = t + j * 0.5
            qname = f"{_encoded_label(rng, 40)}.{domain}"
            events.append((ts, _pkt(proto="DNS", src="10.70.0.5", dst="10.0.0.53", dns_qr=0, dns_qname=qname, dns_qtype="TXT", ts=ts)))
        t += 30.0

    # Benign: ordinary lookups, including long-but-real hostnames (adversarial - must NOT trigger).
    benign_hosts = [
        "www.example.com",
        "static-cdn-assets-eu-west-1.cloudfront-benign.test",
        "mail.corp-internal-services.test",
        "api.thirdpartyanalyticsvendor.test",
    ]
    for i in range(n_benign_domains):
        ts = t + i * 1.0
        host = rng.choice(benign_hosts)
        events.append((ts, _pkt(proto="DNS", src="192.168.3.10", dst="10.0.0.53", dns_qr=0, dns_qname=host, dns_qtype="A", ts=ts)))
        domain = ".".join(host.rsplit(".", 2)[-2:])
        labels.setdefault(domain, False)

    events.sort(key=lambda e: e[0])
    return events, labels


def _flow(duration, packet_count, byte_count, syn_count, flag_diversity, proto="TCP", src="10.0.0.5", dst="10.0.0.1", dport=443) -> Flow:
    flow = Flow(proto=proto, src=src, sport=40000, dst=dst, dport=dport, start_ts=0.0, last_ts=duration)
    flow.packet_count = packet_count
    flow.byte_count = byte_count
    flow.syn_count = syn_count
    flow.flags_seen = {f"F{i}" for i in range(flag_diversity)} or {"S"}
    return flow


def generate_ml_train_flows(seed: int = 1337, n: int = 800) -> list[Flow]:
    """A synthetic benign baseline: short, low-volume, low-diversity flows."""
    rng = random.Random(seed + 3)
    flows = []
    for i in range(n):
        duration = rng.uniform(0.1, 8.0)
        packets = rng.randint(2, 20)
        avg_size = rng.uniform(60, 1200)
        src = f"192.168.10.{i % 250 + 1}"
        flows.append(
            _flow(duration, packets, int(packets * avg_size), syn_count=rng.randint(0, 1), flag_diversity=rng.randint(1, 2), src=src)
        )
    return flows


def generate_ml_eval_cases(seed: int = 1337, n_benign: int = 150, n_anomalous: int = 30):
    """Benign hold-out flows (should NOT alert) + clearly anomalous flows (should alert).

    Each case gets a distinct flow key (unique source) - the detector's cooldown
    is keyed by (src, dst, dport), and this eval's synthetic cases are not
    generated in chronological order, so a shared key would let the cooldown
    gate suppress later cases whose synthetic timestamp happens to be earlier
    than a prior case's - an artifact of this offline corpus, not of real
    streaming use where packets always arrive in non-decreasing time order.
    """
    rng = random.Random(seed + 4)
    cases: list[tuple[Flow, bool]] = []
    for i in range(n_benign):
        duration = rng.uniform(0.1, 8.0)
        packets = rng.randint(2, 20)
        avg_size = rng.uniform(60, 1200)
        src = f"192.168.20.{i % 250 + 1}"
        cases.append(
            (_flow(duration, packets, int(packets * avg_size), syn_count=rng.randint(0, 1), flag_diversity=rng.randint(1, 2), src=src), False)
        )
    for i in range(n_anomalous):
        # Long-lived, huge-volume, highly repetitive flows - e.g. a slow exfil drip or a flood.
        duration = rng.uniform(600.0, 3600.0)
        packets = rng.randint(5000, 50000)
        avg_size = rng.uniform(1400, 1500)
        src = f"10.90.0.{i % 250 + 1}"
        cases.append(
            (_flow(duration, packets, int(packets * avg_size), syn_count=rng.randint(50, 500), flag_diversity=1, src=src), True)
        )
    return cases
