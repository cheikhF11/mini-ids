#!/usr/bin/env python3
"""Offline, no-root, no-network demo: builds a synthetic packet stream (a port
scan, a brute-force burst, a DNS-tunneling attempt, and ordinary traffic),
runs it through a fully wired :class:`IDSEngine`, and prints every alert as
it fires plus a final summary - a self-contained way to see mini-ids catch
something without any lab setup.

    python samples/demo_run.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

from detectors.brute_force import BruteForceDetector
from detectors.exfil import ExfilDetector
from detectors.port_scan import PortScanDetector
from engine.flows import FlowTable
from engine.pipeline import IDSEngine
from rules.matcher import RuleMatcher
from rules.parser import parse_dir
from storage.store import IDSStore

_SRC_MAC, _DST_MAC = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


def _eth():
    return Ether(src=_SRC_MAC, dst=_DST_MAC)


def build_demo_packets() -> list:
    packets = []

    # 1. Ordinary web browsing - should never alert.
    for i, port in enumerate([80, 443, 8443]):
        packets.append(_eth() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51000 + i, dport=port, flags="S"))

    # 2. A SYN port scan against 10.0.0.1 from one attacker.
    for i, port in enumerate(range(20, 45)):
        packets.append(_eth() / IP(src="203.0.113.9", dst="10.0.0.1") / TCP(sport=40000 + i, dport=port, flags="S"))

    # 3. An SSH brute-force burst against 10.0.0.22.
    for i in range(6):
        packets.append(_eth() / IP(src="203.0.113.44", dst="10.0.0.22") / TCP(sport=53000 + i, dport=22, flags="S"))

    # 4. A DNS-tunneling attempt: long, high-entropy labels under one domain.
    for i in range(5):
        qname = f"kq7z2mplsx9vbtaewrfy4hj0az3fp9{i}.tunnel-evil.test"
        packets.append(
            _eth() / IP(src="10.0.0.77", dst="10.0.0.53") / UDP(sport=54000 + i, dport=53) / DNS(qr=0, qd=DNSQR(qname=qname, qtype="TXT"))
        )

    return packets


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "demo.db")
        rules = parse_dir("rules/builtin")
        store = IDSStore(db_path)
        flow_table = FlowTable(on_evict=store.log_flow)

        alerts_seen = []
        engine = IDSEngine(
            rule_matcher=RuleMatcher(rules),
            flow_table=flow_table,
            port_scan=PortScanDetector(),
            brute_force=BruteForceDetector(),
            exfil=ExfilDetector(),
            store=store,
            on_alert=alerts_seen.append,
        )

        print("mini-ids offline demo: replaying synthetic traffic through the full detection pipeline\n")
        for pkt in build_demo_packets():
            engine.process(pkt)

        if not alerts_seen:
            print("No alerts fired - something is wrong with the demo traffic.")
            sys.exit(1)

        print(f"{len(alerts_seen)} alert(s) fired:\n")
        for alert in alerts_seen:
            print(f"  [{alert.severity.upper():>8}] {alert.kind:<12} src={alert.src:<15} dst={alert.dst:<20} {alert.detail}")

        print("\nStored stats:")
        print(json.dumps(store.stats(), indent=2))


if __name__ == "__main__":
    main()
