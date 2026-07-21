import json

from cli import build_parser, _cmd_rules_list, _cmd_rules_validate, _cmd_stats


def test_parser_requires_a_command():
    parser = build_parser()
    args = parser.parse_args(["rules", "list"])
    assert args.command == "rules"
    assert args.rules_command == "list"


def test_sniff_subcommand_defaults():
    parser = build_parser()
    args = parser.parse_args(["sniff", "--iface", "lo"])
    assert args.iface == "lo"
    assert args.dashboard is False


def test_replay_subcommand_requires_pcap_path():
    parser = build_parser()
    args = parser.parse_args(["replay", "sample.pcap"])
    assert args.pcap_path == "sample.pcap"


def test_attack_port_scan_requires_target():
    parser = build_parser()
    args = parser.parse_args(["attack", "port-scan", "--target-ip", "127.0.0.1", "--i-understand-lab"])
    assert args.target_ip == "127.0.0.1"
    assert args.override is True


def test_attack_brute_force_defaults():
    parser = build_parser()
    args = parser.parse_args(["attack", "brute-force", "--target-ip", "127.0.0.1"])
    assert args.port == 22
    assert args.attempts == 8
    assert args.override is False


def test_rules_list_prints_loaded_rules(capsys):
    parser = build_parser()
    args = parser.parse_args(["rules", "list", "--rules-dir", "rules/builtin"])
    _cmd_rules_list(args)
    out = capsys.readouterr().out
    assert "1000010" in out


def test_rules_validate_reports_ok(capsys):
    parser = build_parser()
    args = parser.parse_args(["rules", "validate", "--rules-dir", "rules/builtin"])
    _cmd_rules_validate(args)
    out = capsys.readouterr().out
    assert out.startswith("OK:")


def test_stats_prints_json(tmp_path, capsys):
    parser = build_parser()
    db_path = str(tmp_path / "test.db")
    args = parser.parse_args(["stats", "--db-path", db_path])
    _cmd_stats(args)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["total_alerts"] == 0
