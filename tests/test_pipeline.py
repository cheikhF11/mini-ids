"""End-to-end pipeline test: build packets in memory, run them through a fully
wired :class:`IDSEngine`, and check the resulting alerts and stored flows -
no root, no live network, no pcap file needed.
"""

from core.config import BruteForceConfig, ExfilConfig, PortScanConfig
from core.models import Alert
from detectors.brute_force import BruteForceDetector
from detectors.exfil import ExfilDetector
from detectors.port_scan import PortScanDetector
from engine.flows import FlowTable
from engine.pipeline import IDSEngine
from rules.matcher import RuleMatcher
from rules.parser import parse_dir
from storage.store import IDSStore
from tests.helpers import tcp_packet


def _build_engine(tmp_path, clock):
    rules = parse_dir("rules/builtin")
    store = IDSStore(str(tmp_path / "test.db"))
    flow_table = FlowTable(on_evict=store.log_flow, clock=clock)
    engine = IDSEngine(
        rule_matcher=RuleMatcher(rules, clock=clock),
        flow_table=flow_table,
        port_scan=PortScanDetector(PortScanConfig(window_seconds=10.0, port_threshold=5, cooldown=30.0), clock=clock),
        brute_force=BruteForceDetector(BruteForceConfig(window_seconds=60.0, attempt_threshold=4, cooldown=60.0), clock=clock),
        exfil=ExfilDetector(ExfilConfig(), clock=clock),
        store=store,
        clock=clock,
    )
    return engine, store


class _FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_port_scan_traffic_produces_a_stored_alert(tmp_path):
    clock = _FakeClock()
    engine, store = _build_engine(tmp_path, clock)

    for i, port in enumerate(range(20, 30)):
        clock.t = i * 0.1
        engine.process(tcp_packet("10.0.0.5", "10.0.0.1", 40000 + i, port, flags="S"))

    alerts = store.recent_alerts()
    assert any(a["kind"] == "port_scan" for a in alerts)


def test_brute_force_traffic_produces_a_stored_alert(tmp_path):
    clock = _FakeClock()
    engine, store = _build_engine(tmp_path, clock)

    for i in range(5):
        clock.t = i * 2.0
        engine.process(tcp_packet("10.0.0.9", "10.0.0.22", 50000 + i, 22, flags="S"))

    alerts = store.recent_alerts()
    assert any(a["kind"] in ("brute_force", "signature") for a in alerts)


def test_benign_traffic_produces_no_alerts(tmp_path):
    clock = _FakeClock()
    engine, store = _build_engine(tmp_path, clock)

    for i in range(3):
        clock.t = i * 5.0
        engine.process(tcp_packet("192.168.1.10", "93.184.216.34", 51000 + i, [80, 443, 8443][i], flags="S"))

    assert store.recent_alerts() == []


def test_on_packet_and_on_alert_callbacks_fire(tmp_path):
    clock = _FakeClock()
    rules = parse_dir("rules/builtin")
    store = IDSStore(str(tmp_path / "test.db"))
    packets_seen = []
    alerts_seen: list[Alert] = []

    engine = IDSEngine(
        rule_matcher=RuleMatcher(rules, clock=clock),
        flow_table=FlowTable(clock=clock),
        store=store,
        on_packet=packets_seen.append,
        on_alert=alerts_seen.append,
        clock=clock,
    )
    engine.process(tcp_packet("10.0.0.1", "10.0.0.1", 1, 443, flags=0))
    assert len(packets_seen) == 1
    assert len(alerts_seen) == 1  # NULL-scan builtin rule fires on a single flagless packet
    assert alerts_seen[0].kind == "signature"


def test_flow_table_updates_across_packets(tmp_path):
    clock = _FakeClock()
    engine, _store = _build_engine(tmp_path, clock)
    engine.process(tcp_packet("10.0.0.1", "10.0.0.2", 1000, 80, flags="S"))
    engine.process(tcp_packet("10.0.0.1", "10.0.0.2", 1000, 80, flags="SA"))
    assert len(engine.flows) == 1
    flow = engine.flows.all()[0]
    assert flow.packet_count == 2
