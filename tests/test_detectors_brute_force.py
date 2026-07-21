from core.config import BruteForceConfig
from core.models import PacketRecord
from detectors.brute_force import BruteForceDetector


def _syn(src="10.0.0.5", dst="10.0.0.22", dport=22, ts=0.0, sport=50000):
    return PacketRecord(no=0, ts=ts, length=60, proto="TCP", src=src, dst=dst, sport=sport, dport=dport, tcp_flags="S")


def _established(src="10.0.0.5", dst="10.0.0.22", dport=22, ts=0.0):
    return PacketRecord(no=0, ts=ts, length=60, proto="TCP", src=src, dst=dst, sport=50000, dport=dport, tcp_flags="SA")


def test_fires_after_attempt_threshold():
    detector = BruteForceDetector(BruteForceConfig(window_seconds=60.0, attempt_threshold=3, ports=(22,), cooldown=60.0))
    assert detector.observe(_syn(ts=0.0), now=0.0) is None
    assert detector.observe(_syn(ts=1.0), now=1.0) is None
    alert = detector.observe(_syn(ts=2.0), now=2.0)
    assert alert is not None
    assert alert.kind == "brute_force"


def test_ignores_non_sensitive_ports():
    detector = BruteForceDetector(BruteForceConfig(ports=(22,), attempt_threshold=2))
    for i in range(5):
        alert = detector.observe(_syn(dport=8080, ts=float(i)), now=float(i))
        assert alert is None


def test_established_connections_do_not_count():
    detector = BruteForceDetector(BruteForceConfig(ports=(22,), attempt_threshold=2))
    for i in range(5):
        alert = detector.observe(_established(ts=float(i)), now=float(i))
        assert alert is None


def test_legitimate_retries_below_threshold_do_not_fire():
    detector = BruteForceDetector(BruteForceConfig(ports=(22,), attempt_threshold=5))
    for i in range(2):
        alert = detector.observe(_syn(ts=float(i)), now=float(i))
        assert alert is None


def test_window_expiry_resets_count():
    detector = BruteForceDetector(BruteForceConfig(window_seconds=5.0, attempt_threshold=3, ports=(22,)))
    detector.observe(_syn(ts=0.0), now=0.0)
    detector.observe(_syn(ts=1.0), now=1.0)
    alert = detector.observe(_syn(ts=100.0), now=100.0)
    assert alert is None


def test_cooldown_suppresses_repeat_alerts():
    detector = BruteForceDetector(BruteForceConfig(attempt_threshold=2, cooldown=60.0))
    detector.observe(_syn(ts=0.0), now=0.0)
    first = detector.observe(_syn(ts=1.0), now=1.0)
    assert first is not None
    second = detector.observe(_syn(ts=2.0), now=2.0)
    assert second is None
