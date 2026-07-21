from core.config import MLConfig
from core.models import Flow
from detectors.ml_anomaly import MLAnomalyDetector, flow_features


def _flow(duration, packets, byte_count, syn_count=0, flag_diversity=1, src="10.0.0.5", dst="10.0.0.1", dport=443):
    flow = Flow(proto="TCP", src=src, sport=40000, dst=dst, dport=dport, start_ts=0.0, last_ts=duration)
    flow.packet_count = packets
    flow.byte_count = byte_count
    flow.syn_count = syn_count
    flow.flags_seen = {f"F{i}" for i in range(flag_diversity)}
    return flow


def _train_flows(n=200, seed_offset=0):
    return [_flow(duration=(i % 8) + 0.5, packets=(i % 15) + 2, byte_count=((i % 15) + 2) * 300, src=f"10.1.0.{i % 250 + 1}") for i in range(n)]


def test_predict_returns_none_before_training():
    detector = MLAnomalyDetector(MLConfig())
    flow = _flow(duration=1000.0, packets=50000, byte_count=50000 * 1400)
    assert detector.predict(flow, now=1.0) is None


def test_predict_flags_extreme_flow_after_training():
    detector = MLAnomalyDetector(MLConfig(contamination=0.02, min_flow_packets=2, cooldown=0.0))
    detector.train(_train_flows())
    anomalous = _flow(duration=3000.0, packets=40000, byte_count=40000 * 1450, syn_count=200, src="10.9.0.9")
    alert = detector.predict(anomalous, now=3001.0)
    assert alert is not None
    assert alert.kind == "ml_anomaly"


def test_predict_does_not_flag_typical_flow_after_training():
    detector = MLAnomalyDetector(MLConfig(contamination=0.02, min_flow_packets=2, cooldown=0.0))
    detector.train(_train_flows())
    typical = _flow(duration=2.0, packets=10, byte_count=10 * 400, src="10.1.0.222")
    assert detector.predict(typical, now=2.0) is None


def test_predict_respects_min_flow_packets():
    detector = MLAnomalyDetector(MLConfig(min_flow_packets=5))
    detector.train(_train_flows())
    tiny = _flow(duration=1000.0, packets=1, byte_count=1000)
    assert detector.predict(tiny, now=1.0) is None


def test_cooldown_suppresses_repeat_alerts():
    detector = MLAnomalyDetector(MLConfig(contamination=0.02, min_flow_packets=2, cooldown=60.0))
    detector.train(_train_flows())
    anomalous = _flow(duration=3000.0, packets=40000, byte_count=40000 * 1450, syn_count=200, src="10.9.0.9")
    first = detector.predict(anomalous, now=0.0)
    second = detector.predict(anomalous, now=1.0)
    assert first is not None
    assert second is None


def test_save_and_load_round_trip(tmp_path):
    detector = MLAnomalyDetector(MLConfig(contamination=0.02))
    detector.train(_train_flows())
    path = tmp_path / "model.joblib"
    detector.save(str(path))

    reloaded = MLAnomalyDetector(MLConfig(contamination=0.02, min_flow_packets=2, cooldown=0.0))
    reloaded.load(str(path))
    anomalous = _flow(duration=3000.0, packets=40000, byte_count=40000 * 1450, syn_count=200, src="10.9.0.9")
    assert reloaded.predict(anomalous, now=0.0) is not None


def test_flow_features_shape():
    flow = _flow(duration=1.0, packets=5, byte_count=500, syn_count=1, flag_diversity=2)
    features = flow_features(flow)
    assert len(features) == 6
    assert features[1] == 5.0
