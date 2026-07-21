"""mini-ids CLI: sniff / replay / rules / stats / attack (lab-only)."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time

from core.config import add_run_arguments, build_config


def _add_dashboard_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dashboard", action="store_true", help="Also launch the web dashboard")
    parser.add_argument("--dashboard-host", default="127.0.0.1")
    parser.add_argument("--dashboard-port", type=int, default=5000)


def _maybe_launch_dashboard(args, engine, store, rules):
    if not getattr(args, "dashboard", False):
        return None
    from dashboard.app import DashboardApp

    dash = DashboardApp(store=store, rules=rules)
    engine.on_alert = dash.on_alert
    thread = threading.Thread(
        target=dash.run, kwargs={"host": args.dashboard_host, "port": args.dashboard_port}, daemon=True
    )
    thread.start()
    print(f"Dashboard running at http://{args.dashboard_host}:{args.dashboard_port}", file=sys.stderr)
    return dash


def _cmd_sniff(args) -> None:
    from engine.capture import LiveCapture
    from mini_ids import build_engine

    config = build_config(args)
    engine, store, rules = build_engine(config)
    _maybe_launch_dashboard(args, engine, store, rules)

    capture = LiveCapture(engine.process, iface=config.capture.iface, bpf_filter=config.capture.bpf_filter)
    capture.start()
    print(f"Sniffing on {config.capture.iface or 'default interface'}... Ctrl+C to stop", file=sys.stderr)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        capture.stop()
        print("Stopped.", file=sys.stderr)


def _cmd_replay(args) -> None:
    from engine.capture import read_pcap
    from mini_ids import build_engine

    config = build_config(args)
    engine, store, rules = build_engine(config)
    _maybe_launch_dashboard(args, engine, store, rules)

    n = read_pcap(args.pcap_path, engine.process)
    print(f"Replayed {n} packets from {args.pcap_path}", file=sys.stderr)
    print(json.dumps(store.stats(), indent=2))


def _cmd_rules_list(args) -> None:
    from rules.parser import parse_dir

    for rule in parse_dir(args.rules_dir):
        print(f"{rule.sid}\t{rule.proto}\t{rule.severity}\t{rule.msg}")


def _cmd_rules_validate(args) -> None:
    from rules.parser import RuleParseError, parse_dir

    try:
        rules = parse_dir(args.rules_dir)
    except RuleParseError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {len(rules)} rules parsed from {args.rules_dir}")


def _cmd_stats(args) -> None:
    from storage.store import IDSStore

    store = IDSStore(args.db_path)
    print(json.dumps(store.stats(), indent=2))


def _cmd_attack_port_scan(args) -> None:
    from offensive.port_scanner import scan

    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    n = scan(args.target_ip, ports=ports, override=args.override)
    print(f"Sent {n} SYN probes to {args.target_ip}", file=sys.stderr)


def _cmd_attack_brute_force(args) -> None:
    from offensive.brute_force_sim import simulate

    n = simulate(args.target_ip, port=args.port, attempts=args.attempts, override=args.override)
    print(f"Sent {n} connection attempts to {args.target_ip}:{args.port}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mini-ids")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sniff = sub.add_parser("sniff", help="Live capture + full detection pipeline")
    add_run_arguments(p_sniff)
    _add_dashboard_arguments(p_sniff)
    p_sniff.set_defaults(func=_cmd_sniff)

    p_replay = sub.add_parser("replay", help="Replay a pcap file through the detection pipeline")
    add_run_arguments(p_replay)
    p_replay.add_argument("pcap_path")
    _add_dashboard_arguments(p_replay)
    p_replay.set_defaults(func=_cmd_replay)

    p_rules = sub.add_parser("rules", help="Rule management")
    rules_sub = p_rules.add_subparsers(dest="rules_command", required=True)
    p_rules_list = rules_sub.add_parser("list", help="List loaded rules")
    p_rules_list.add_argument("--rules-dir", default="rules/builtin")
    p_rules_list.set_defaults(func=_cmd_rules_list)
    p_rules_validate = rules_sub.add_parser("validate", help="Validate rule syntax")
    p_rules_validate.add_argument("--rules-dir", default="rules/builtin")
    p_rules_validate.set_defaults(func=_cmd_rules_validate)

    p_stats = sub.add_parser("stats", help="Print stats from the SQLite store")
    p_stats.add_argument("--db-path", default="data/mini_ids.db")
    p_stats.set_defaults(func=_cmd_stats)

    p_attack = sub.add_parser("attack", help="Lab-only offensive demo traffic")
    attack_sub = p_attack.add_subparsers(dest="attack_command", required=True)

    p_port_scan = attack_sub.add_parser("port-scan", help="Generate SYN port-scan traffic")
    p_port_scan.add_argument("--target-ip", required=True)
    p_port_scan.add_argument("--ports", default=None, help="Comma-separated port list")
    p_port_scan.add_argument("--i-understand-lab", dest="override", action="store_true")
    p_port_scan.set_defaults(func=_cmd_attack_port_scan)

    p_brute = attack_sub.add_parser("brute-force", help="Generate repeated connection-attempt traffic")
    p_brute.add_argument("--target-ip", required=True)
    p_brute.add_argument("--port", type=int, default=22)
    p_brute.add_argument("--attempts", type=int, default=8)
    p_brute.add_argument("--i-understand-lab", dest="override", action="store_true")
    p_brute.set_defaults(func=_cmd_attack_brute_force)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
