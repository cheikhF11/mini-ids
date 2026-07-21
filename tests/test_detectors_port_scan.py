from core.config import PortScanConfig
from core.models import PacketRecord
from detectors.port_scan import PortScanDetector


def _pkt(dport, flags="S", src="10.0.0.5", ts=0.0):
    return PacketRecord(no=0, ts=ts, length=60, proto="TCP", src=src, dst="10.0.0.1", sport=40000, dport=dport, tcp_flags=flags)


def test_fires_after_distinct_port_threshold_reached():
    detector = PortScanDetector(PortScanConfig(window_seconds=10.0, port_threshold=5, cooldown=30.0))
    alerts = [detector.observe(_pkt(dport=p), now=float(i)) for i, p in enumerate(range(10, 14))]
    assert alerts == [None, None, None, None]
    alert = detector.observe(_pkt(dport=14), now=4.0)
    assert alert is not None
    assert alert.kind == "port_scan"
    assert alert.src == "10.0.0.5"


def test_does_not_fire_below_threshold():
    detector = PortScanDetector(PortScanConfig(window_seconds=10.0, port_threshold=10, cooldown=30.0))
    alerts = [detector.observe(_pkt(dport=p), now=float(i)) for i, p in enumerate(range(10, 15))]
    assert all(a is None for a in alerts)


def test_old_ports_expire_out_of_window():
    detector = PortScanDetector(PortScanConfig(window_seconds=5.0, port_threshold=3, cooldown=30.0))
    detector.observe(_pkt(dport=10), now=0.0)
    detector.observe(_pkt(dport=11), now=1.0)
    # far outside the window - the first two ports should no longer count toward the threshold
    alert = detector.observe(_pkt(dport=12), now=100.0)
    assert alert is None


def test_cooldown_suppresses_repeat_alerts():
    detector = PortScanDetector(PortScanConfig(window_seconds=10.0, port_threshold=3, cooldown=30.0))
    for i, p in enumerate(range(10, 12)):  # 2 distinct ports - stays below the threshold of 3
        detector.observe(_pkt(dport=p), now=float(i))
    first = detector.observe(_pkt(dport=13), now=3.0)  # 3rd distinct port crosses the threshold
    assert first is not None
    second = detector.observe(_pkt(dport=14), now=4.0)
    assert second is None  # within cooldown


def test_classifies_syn_scan():
    detector = PortScanDetector(PortScanConfig(window_seconds=10.0, port_threshold=3, cooldown=30.0))
    for i, p in enumerate(range(10, 12)):
        detector.observe(_pkt(dport=p, flags="S"), now=float(i))
    alert = detector.observe(_pkt(dport=13, flags="S"), now=3.0)
    assert "SYN" in alert.detail


def test_classifies_null_scan():
    detector = PortScanDetector(PortScanConfig(window_seconds=10.0, port_threshold=3, cooldown=30.0))
    for i, p in enumerate(range(10, 12)):
        detector.observe(_pkt(dport=p, flags=""), now=float(i))
    alert = detector.observe(_pkt(dport=13, flags=""), now=3.0)
    assert "NULL" in alert.detail


def test_ignores_packets_without_dport():
    detector = PortScanDetector()
    pkt = PacketRecord(no=0, ts=0.0, length=60, proto="ARP", src="10.0.0.5", dst="10.0.0.1")
    assert detector.observe(pkt) is None
