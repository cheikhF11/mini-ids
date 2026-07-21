from core.models import PacketRecord
from engine.flows import FlowTable


def _pkt(ts, src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=80, flags="S", length=60):
    return PacketRecord(no=0, ts=ts, length=length, proto="TCP", src=src, dst=dst, sport=sport, dport=dport, tcp_flags=flags)


def test_flow_aggregates_packets_in_same_5_tuple():
    table = FlowTable()
    table.update(_pkt(0.0))
    flow = table.update(_pkt(0.5))
    assert flow.packet_count == 2
    assert flow.byte_count == 120
    assert flow.duration == 0.5


def test_flow_tracks_flags_and_syn_count():
    table = FlowTable()
    table.update(_pkt(0.0, flags="S"))
    flow = table.update(_pkt(0.1, flags="SA"))
    assert flow.flags_seen == {"S", "SA"}
    assert flow.syn_count == 1  # only the bare "S" (no ack) counts as a fresh attempt


def test_distinct_5_tuples_are_separate_flows():
    table = FlowTable()
    table.update(_pkt(0.0, dport=80))
    table.update(_pkt(0.0, dport=443))
    assert len(table) == 2


def test_idle_flows_are_evicted():
    table = FlowTable(idle_timeout=10.0)
    table.update(_pkt(0.0))
    table.update(_pkt(100.0, src="10.0.0.9"))  # far enough ahead to expire the first flow
    assert len(table) == 1


def test_eviction_invokes_on_evict_callback():
    evicted = []
    table = FlowTable(idle_timeout=10.0, on_evict=evicted.append)
    table.update(_pkt(0.0))
    table.update(_pkt(100.0, src="10.0.0.9"))
    assert len(evicted) == 1
    assert evicted[0].src == "10.0.0.1"


def test_ignores_packets_without_addresses():
    table = FlowTable()
    pkt = PacketRecord(no=0, ts=0.0, length=0)
    assert table.update(pkt) is None
