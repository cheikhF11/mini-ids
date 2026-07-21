"""Detection-accuracy eval: seeded synthetic corpora -> precision/recall/F1
per detector category, gated against a configurable threshold.

Run with ``python -m evals.run_detection``. This is a periodic/paid-in-spirit
eval (slower, quality-measuring), distinct from the free/fast ``pytest -q``
gate suite - see the project's two-lane testing policy.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.config import BruteForceConfig, ExfilConfig, MLConfig, PortScanConfig
from detectors.brute_force import BruteForceDetector
from detectors.exfil import ExfilDetector
from detectors.ml_anomaly import MLAnomalyDetector
from detectors.port_scan import PortScanDetector
from evals.corpus import (
    generate_brute_force_cases,
    generate_exfil_cases,
    generate_ml_eval_cases,
    generate_ml_train_flows,
    generate_port_scan_cases,
)


def _confusion(labels: dict[str, bool], predicted_positive: set[str]) -> tuple[dict, list[dict]]:
    tp = fp = tn = fn = 0
    rows = []
    for key, label in labels.items():
        pred = key in predicted_positive
        if label and pred:
            tp += 1
        elif label and not pred:
            fn += 1
        elif not label and pred:
            fp += 1
        else:
            tn += 1
        rows.append({"case": key, "label": label, "predicted": pred})
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1}, rows


def run_port_scan(seed: int) -> tuple[dict, list[dict]]:
    events, labels = generate_port_scan_cases(seed=seed)
    detector = PortScanDetector(PortScanConfig())
    predicted: set[str] = set()
    for ts, pkt in events:
        alert = detector.observe(pkt, now=ts)
        if alert is not None:
            predicted.add(alert.src)
    return _confusion(labels, predicted)


def run_brute_force(seed: int) -> tuple[dict, list[dict]]:
    events, labels = generate_brute_force_cases(seed=seed)
    detector = BruteForceDetector(BruteForceConfig())
    predicted: set[str] = set()
    for ts, pkt in events:
        alert = detector.observe(pkt, now=ts)
        if alert is not None:
            predicted.add(alert.src)
    return _confusion(labels, predicted)


def run_exfil(seed: int) -> tuple[dict, list[dict]]:
    events, labels = generate_exfil_cases(seed=seed)
    detector = ExfilDetector(ExfilConfig())
    predicted: set[str] = set()
    for ts, pkt in events:
        alert = detector.observe(pkt, now=ts)
        if alert is not None:
            predicted.add(alert.dst)  # dst holds the registered domain for exfil alerts
    return _confusion(labels, predicted)


def run_ml(seed: int) -> tuple[dict, list[dict], MLAnomalyDetector]:
    train_flows = generate_ml_train_flows(seed=seed)
    detector = MLAnomalyDetector(MLConfig(contamination=0.01, min_flow_packets=2, cooldown=0.0))
    detector.train(train_flows)

    cases = generate_ml_eval_cases(seed=seed)
    tp = fp = tn = fn = 0
    rows = []
    for flow, label in cases:
        alert = detector.predict(flow, now=flow.last_ts + 1)
        pred = alert is not None
        if label and pred:
            tp += 1
        elif label and not pred:
            fn += 1
        elif not label and pred:
            fp += 1
        else:
            tn += 1
        rows.append({"case": f"{flow.src}->{flow.dst}:{flow.dport}", "label": label, "predicted": pred})

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1}, rows, detector


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="mini-ids detection-accuracy eval")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--precision-port-scan", type=float, default=0.90)
    parser.add_argument("--recall-port-scan", type=float, default=0.95)
    parser.add_argument("--precision-brute-force", type=float, default=0.90)
    parser.add_argument("--recall-brute-force", type=float, default=0.95)
    parser.add_argument("--precision-exfil", type=float, default=0.90)
    parser.add_argument("--recall-exfil", type=float, default=0.90)
    parser.add_argument("--precision-ml", type=float, default=0.80)
    parser.add_argument("--recall-ml", type=float, default=0.80)
    args = parser.parse_args(argv)

    thresholds = {
        "port_scan": (args.precision_port_scan, args.recall_port_scan),
        "brute_force": (args.precision_brute_force, args.recall_brute_force),
        "exfil": (args.precision_exfil, args.recall_exfil),
        "ml_anomaly": (args.precision_ml, args.recall_ml),
    }

    results: dict[str, dict] = {}
    all_rows: list[dict] = []

    conf, rows = run_port_scan(args.seed)
    results["port_scan"] = conf
    all_rows += [{"category": "port_scan", **r} for r in rows]

    conf, rows = run_brute_force(args.seed)
    results["brute_force"] = conf
    all_rows += [{"category": "brute_force", **r} for r in rows]

    conf, rows = run_exfil(args.seed)
    results["exfil"] = conf
    all_rows += [{"category": "exfil", **r} for r in rows]

    conf, rows, ml_detector = run_ml(args.seed)
    results["ml_anomaly"] = conf
    all_rows += [{"category": "ml_anomaly", **r} for r in rows]
    ml_detector.save()  # persist the trained model for `--enable-ml` runtime use

    out_path = Path(__file__).parent / "corpus" / "dataset.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for row in all_rows:
            f.write(json.dumps(row) + "\n")

    print(f"{'category':<14}{'precision':>10}{'recall':>10}{'f1':>8}{'tp':>6}{'fp':>6}{'tn':>6}{'fn':>6}")
    ok = True
    for name, conf in results.items():
        p_min, r_min = thresholds[name]
        print(
            f"{name:<14}{conf['precision']:>10.2f}{conf['recall']:>10.2f}{conf['f1']:>8.2f}"
            f"{conf['tp']:>6}{conf['fp']:>6}{conf['tn']:>6}{conf['fn']:>6}"
        )
        if conf["precision"] < p_min or conf["recall"] < r_min:
            ok = False
            print(f"  GATE FAILED: {name} precision={conf['precision']:.2f} (min {p_min}) recall={conf['recall']:.2f} (min {r_min})")

    print(f"\nWrote {len(all_rows)} scored rows to {out_path}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
