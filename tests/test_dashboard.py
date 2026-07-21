from core.models import Alert
from dashboard.app import DashboardApp
from rules.schema import Rule
from storage.store import IDSStore


def _make_app(tmp_path):
    store = IDSStore(str(tmp_path / "test.db"))
    rules = [Rule(sid=1000010, msg="NULL scan detected", proto="tcp", severity="high")]
    dash = DashboardApp(store=store, rules=rules, auto_start=False)
    return dash, store


def test_index_renders(tmp_path):
    dash, _store = _make_app(tmp_path)
    client = dash.app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"mini-ids" in resp.data


def test_api_stats_reflects_store(tmp_path):
    dash, store = _make_app(tmp_path)
    store.log_alert(Alert(kind="port_scan", severity="high", src="10.0.0.5", dst="", detail="d", ts=1.0))
    client = dash.app.test_client()
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    assert resp.get_json()["total_alerts"] == 1


def test_api_alerts_returns_recent(tmp_path):
    dash, store = _make_app(tmp_path)
    store.log_alert(Alert(kind="port_scan", severity="high", src="10.0.0.5", dst="", detail="d", ts=1.0))
    client = dash.app.test_client()
    resp = client.get("/api/alerts?limit=10")
    rows = resp.get_json()
    assert len(rows) == 1
    assert rows[0]["kind"] == "port_scan"


def test_api_rules_lists_loaded_rules(tmp_path):
    dash, _store = _make_app(tmp_path)
    client = dash.app.test_client()
    resp = client.get("/api/rules")
    rows = resp.get_json()
    assert rows == [{"sid": 1000010, "msg": "NULL scan detected", "severity": "high", "proto": "tcp"}]


def test_on_alert_buffers_pending_alerts(tmp_path):
    dash, _store = _make_app(tmp_path)
    alert = Alert(kind="port_scan", severity="high", src="10.0.0.5", dst="", detail="d", ts=1.0)
    dash.on_alert(alert)
    assert len(dash._pending_alerts) == 1
    assert dash._pending_alerts[0]["kind"] == "port_scan"
