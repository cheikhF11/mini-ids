from scapy.utils import wrpcap

from engine.capture import LiveCapture, read_pcap, replay_pcap
from tests.helpers import tcp_packet


def test_read_pcap_round_trip(tmp_path):
    packets = [tcp_packet("10.0.0.1", "10.0.0.2", 1000 + i, 80) for i in range(5)]
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)

    seen = []
    n = read_pcap(str(path), seen.append)
    assert n == 5
    assert len(seen) == 5


def test_read_pcap_respects_count(tmp_path):
    packets = [tcp_packet("10.0.0.1", "10.0.0.2", 1000 + i, 80) for i in range(10)]
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)

    seen = []
    n = read_pcap(str(path), seen.append, count=3)
    assert n == 3
    assert len(seen) == 3


def test_replay_pcap_uses_injected_sleep(tmp_path):
    packets = [tcp_packet("10.0.0.1", "10.0.0.2", 1000 + i, 80) for i in range(3)]
    for i, pkt in enumerate(packets):
        pkt.time = i * 2.0
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)

    sleeps = []
    seen = []
    n = replay_pcap(str(path), seen.append, speed=1.0, max_gap=5.0, sleep_fn=sleeps.append)
    assert n == 3
    assert len(seen) == 3
    assert sleeps == [2.0, 2.0]


def test_replay_pcap_respects_stop_flag(tmp_path):
    packets = [tcp_packet("10.0.0.1", "10.0.0.2", 1000 + i, 80) for i in range(5)]
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)

    seen = []
    n = replay_pcap(str(path), seen.append, sleep_fn=lambda s: None, stop_flag=lambda: len(seen) >= 2)
    assert n == 2


def test_live_capture_construction_does_not_start_sniffer():
    calls = []
    capture = LiveCapture(prn=calls.append, iface="lo", bpf_filter="tcp")
    assert capture.iface == "lo"
    assert capture.bpf_filter == "tcp"
    assert capture._sniffer is None
