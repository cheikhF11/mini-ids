from core.models import Alert, Flow
from storage.store import IDSStore


def _alert(kind="port_scan", severity="high", src="10.0.0.5"):
    return Alert(kind=kind, severity=severity, src=src, dst="10.0.0.1", detail="detail", ts=1.0, sid=1000010, score=2.0)


def _flow():
    flow = Flow(proto="TCP", src="10.0.0.5", sport=40000, dst="10.0.0.1", dport=22, start_ts=0.0, last_ts=5.0)
    flow.packet_count = 10
    flow.byte_count = 600
    flow.flags_seen = {"S", "SA"}
    return flow


def test_log_and_recent_alerts(tmp_path):
    store = IDSStore(str(tmp_path / "test.db"))
    store.log_alert(_alert())
    store.log_alert(_alert(kind="brute_force"))
    rows = store.recent_alerts()
    assert len(rows) == 2
    assert rows[0]["kind"] == "brute_force"  # most recent first (same ts, insertion order via id)


def test_log_and_recent_flows(tmp_path):
    store = IDSStore(str(tmp_path / "test.db"))
    store.log_flow(_flow())
    rows = store.recent_flows()
    assert len(rows) == 1
    assert rows[0]["packet_count"] == 10


def test_stats_aggregate(tmp_path):
    store = IDSStore(str(tmp_path / "test.db"))
    store.log_alert(_alert(kind="port_scan", severity="high", src="10.0.0.5"))
    store.log_alert(_alert(kind="port_scan", severity="high", src="10.0.0.5"))
    store.log_alert(_alert(kind="brute_force", severity="medium", src="10.0.0.6"))
    store.log_flow(_flow())

    stats = store.stats()
    assert stats["total_alerts"] == 3
    assert stats["alerts_by_kind"]["port_scan"] == 2
    assert stats["alerts_by_severity"]["high"] == 2
    assert stats["total_flows"] == 1
    assert stats["top_sources"][0]["src"] == "10.0.0.5"
    assert stats["top_sources"][0]["count"] == 2


def test_store_persists_across_reopen(tmp_path):
    path = str(tmp_path / "test.db")
    store = IDSStore(path)
    store.log_alert(_alert())
    store.close()

    reopened = IDSStore(path)
    assert reopened.stats()["total_alerts"] == 1
