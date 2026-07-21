import pytest
from scapy.layers.inet import TCP

from offensive.brute_force_sim import build_attempt_packets, simulate
from offensive.guard import LabGuardError, is_lab_target, require_lab_target
from offensive.port_scanner import build_syn_packets, scan


def test_is_lab_target_accepts_loopback_and_private():
    assert is_lab_target("127.0.0.1") is True
    assert is_lab_target("10.0.0.5") is True
    assert is_lab_target("192.168.1.1") is True


def test_is_lab_target_rejects_public_ip():
    assert is_lab_target("8.8.8.8") is False


def test_require_lab_target_raises_for_public_target():
    with pytest.raises(LabGuardError):
        require_lab_target("8.8.8.8")


def test_require_lab_target_allows_override():
    require_lab_target("8.8.8.8", override=True)  # must not raise


def test_build_syn_packets_targets_every_port():
    packets = build_syn_packets("10.0.0.1", [22, 80, 443])
    assert len(packets) == 3
    assert packets[0][TCP].dport == 22


def test_scan_refuses_public_target():
    with pytest.raises(LabGuardError):
        scan("8.8.8.8", ports=[22])


def test_scan_uses_injected_send_fn():
    sent = []
    n = scan("127.0.0.1", ports=[22, 80], send_fn=sent.append, sleep_fn=lambda s: None)
    assert n == 2
    assert len(sent) == 2


def test_build_attempt_packets_reuses_same_port():
    packets = build_attempt_packets("10.0.0.1", 22, attempts=4)
    assert len(packets) == 4
    assert all(pkt[TCP].dport == 22 for pkt in packets)
    assert len({pkt[TCP].sport for pkt in packets}) == 4  # distinct source ports per attempt


def test_simulate_refuses_public_target():
    with pytest.raises(LabGuardError):
        simulate("8.8.8.8")


def test_simulate_uses_injected_send_fn():
    sent = []
    n = simulate("127.0.0.1", port=22, attempts=5, send_fn=sent.append, sleep_fn=lambda s: None)
    assert n == 5
    assert len(sent) == 5
