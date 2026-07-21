"""mini-ids engine assembly: wires rules, detectors, storage and alert sinks
into one :class:`engine.pipeline.IDSEngine`, importable standalone or from
``cli.py``.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from alerts.console_sink import make_console_sink
from alerts.dispatcher import AlertDispatcher
from alerts.email_sink import make_email_sink
from alerts.log_sink import make_log_sink
from alerts.webhook_sink import make_webhook_sink
from core.config import IDSConfig, add_run_arguments, build_config  # noqa: F401 (re-exported)
from core.models import Alert, PacketRecord
from detectors.brute_force import BruteForceDetector
from detectors.exfil import ExfilDetector
from detectors.ml_anomaly import MLAnomalyDetector
from detectors.port_scan import PortScanDetector
from engine.flows import FlowTable
from engine.pipeline import IDSEngine
from rules.matcher import RuleMatcher
from rules.parser import parse_dir
from storage.store import IDSStore


def build_engine(
    config: IDSConfig,
    on_packet: Optional[Callable[[PacketRecord], None]] = None,
    on_alert: Optional[Callable[[Alert], None]] = None,
    clock: Callable[[], float] = time.time,
) -> tuple[IDSEngine, IDSStore, list]:
    """Build a fully-wired :class:`IDSEngine` from an :class:`IDSConfig`."""
    rules = parse_dir(config.rules.rules_dir)
    rule_matcher = RuleMatcher(rules, clock=clock)

    store = IDSStore(config.db_path)
    flow_table = FlowTable(on_evict=store.log_flow, clock=clock)

    port_scan = PortScanDetector(config.port_scan, clock=clock)
    brute_force = BruteForceDetector(config.brute_force, clock=clock)
    exfil = ExfilDetector(config.exfil, clock=clock)

    ml = None
    if config.ml.enabled:
        ml = MLAnomalyDetector(config.ml)
        try:
            ml.load()
        except Exception:
            ml = None  # no trained model on disk yet - run `python -m evals.run_detection` to train one

    dispatcher = AlertDispatcher(config.alerts, clock=clock)
    if config.alerts.console_enabled:
        dispatcher.register(make_console_sink())
    dispatcher.register(make_log_sink(config.alerts.log_path))
    dispatcher.register(make_email_sink(config.alerts))
    dispatcher.register(make_webhook_sink(config.alerts))

    engine = IDSEngine(
        rule_matcher=rule_matcher,
        flow_table=flow_table,
        port_scan=port_scan,
        brute_force=brute_force,
        exfil=exfil,
        ml=ml,
        store=store,
        dispatcher=dispatcher,
        on_packet=on_packet,
        on_alert=on_alert,
        clock=clock,
    )
    return engine, store, rules


def main(argv: Optional[list[str]] = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="mini_ids", description="mini-ids: lightweight IDS engine")
    add_run_arguments(parser)
    parser.add_argument("--pcap", default=None, help="Replay a pcap file instead of live capture")
    args = parser.parse_args(argv)

    config = build_config(args)
    engine, _store, _rules = build_engine(config)

    if args.pcap:
        from engine.capture import read_pcap

        n = read_pcap(args.pcap, engine.process)
        print(f"Replayed {n} packets from {args.pcap}")
        return

    from engine.capture import LiveCapture

    capture = LiveCapture(engine.process, iface=config.capture.iface, bpf_filter=config.capture.bpf_filter)
    capture.start()
    print(f"Sniffing on {config.capture.iface or 'default interface'}... Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        capture.stop()
        print("Stopped.")


if __name__ == "__main__":
    main()
