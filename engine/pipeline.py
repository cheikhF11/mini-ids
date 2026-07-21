"""IDSEngine: the single dispatch pipeline behind both the CLI and dashboard.

``process(pkt)`` is transport-agnostic - it doesn't care whether the packet
came from a live NIC or a replayed pcap. Every sub-component is passed in
already constructed (dependency injection), so the whole pipeline is testable
with fakes and without touching the network or a database.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from scapy.packet import Packet

from core.models import Alert, PacketRecord
from engine.dissect import dissect
from engine.flows import FlowTable
from rules.matcher import RuleMatcher


class IDSEngine:
    def __init__(
        self,
        rule_matcher: RuleMatcher,
        flow_table: FlowTable,
        port_scan=None,
        brute_force=None,
        exfil=None,
        ml=None,
        store=None,
        dispatcher=None,
        on_packet: Optional[Callable[[PacketRecord], None]] = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.rule_matcher = rule_matcher
        self.flows = flow_table
        self.port_scan = port_scan
        self.brute_force = brute_force
        self.exfil = exfil
        self.ml = ml
        self.store = store
        self.dispatcher = dispatcher
        self.on_packet = on_packet
        self.on_alert = on_alert
        self._clock = clock
        self._counter = 0

    def process(self, pkt: Packet) -> PacketRecord:
        now = self._clock()
        rec = dissect(pkt, no=self._counter, ts=now)
        self._counter += 1

        flow = self.flows.update(rec)

        alerts: list[Alert] = list(self.rule_matcher.match(rec, now=now))
        for detector in (self.port_scan, self.brute_force, self.exfil):
            if detector is None:
                continue
            alert = detector.observe(rec, now=now)
            if alert is not None:
                alerts.append(alert)
        if self.ml is not None and flow is not None:
            alert = self.ml.predict(flow, now=now)
            if alert is not None:
                alerts.append(alert)

        for alert in alerts:
            if self.store is not None:
                self.store.log_alert(alert)
            if self.dispatcher is not None:
                self.dispatcher.dispatch(alert, now=now)
            if self.on_alert is not None:
                self.on_alert(alert)

        if self.on_packet is not None:
            self.on_packet(rec)

        return rec
