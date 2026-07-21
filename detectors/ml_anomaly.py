"""Optional ML anomaly detector: IsolationForest over per-flow features.

Complements the signature/behavioral detectors with an unsupervised model
that can flag traffic shapes none of the hand-written rules anticipated.
Trained on a synthetic benign baseline (see ``evals/corpus.py``), persisted
with joblib, and gated behind ``MLConfig.enabled`` / ``--enable-ml`` so the
default run stays dependency-light and demo-safe.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from core.config import MLConfig
from core.models import Alert, Flow

FEATURE_NAMES = ["duration", "packet_count", "byte_count", "avg_packet_size", "syn_count", "flag_diversity"]


def flow_features(flow: Flow) -> list[float]:
    return [
        float(flow.duration),
        float(flow.packet_count),
        float(flow.byte_count),
        float(flow.avg_packet_size),
        float(flow.syn_count),
        float(len(flow.flags_seen)),
    ]


class MLAnomalyDetector:
    def __init__(self, config: Optional[MLConfig] = None):
        self.cfg = config or MLConfig()
        self.model = None
        self._last_alert: dict[tuple, float] = {}

    def train(self, flows: list[Flow]) -> None:
        from sklearn.ensemble import IsolationForest

        X = [flow_features(f) for f in flows]
        self.model = IsolationForest(contamination=self.cfg.contamination, random_state=42, n_estimators=200)
        self.model.fit(X)

    def save(self, path: Optional[str] = None) -> None:
        import joblib

        target = Path(path or self.cfg.model_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, target)

    def load(self, path: Optional[str] = None) -> None:
        import joblib

        self.model = joblib.load(path or self.cfg.model_path)

    def predict(self, flow: Flow, now: Optional[float] = None) -> Optional[Alert]:
        if self.model is None or flow.packet_count < self.cfg.min_flow_packets:
            return None
        now = now if now is not None else time.time()

        x = [flow_features(flow)]
        prediction = self.model.predict(x)[0]
        if prediction != -1:
            return None

        key = (flow.src, flow.dst, flow.dport)
        last = self._last_alert.get(key)
        if last is not None and now - last < self.cfg.cooldown:
            return None
        self._last_alert[key] = now

        score = float(-self.model.score_samples(x)[0])
        detail = f"Anomalous flow {flow.src}->{flow.dst}:{flow.dport} ({flow.proto}), score={score:.3f}"
        return Alert(kind="ml_anomaly", severity="medium", src=flow.src, dst=flow.dst, detail=detail, ts=now, score=score)
