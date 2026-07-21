import pytest

from rules.parser import RuleParseError, parse_dir, parse_file, parse_rule


def test_parse_simple_signature_rule():
    line = 'alert tcp any any -> any 80 (msg:"test rule"; content:"GET /"; nocase; sid:1; severity:high;)'
    rule = parse_rule(line)
    assert rule.sid == 1
    assert rule.msg == "test rule"
    assert rule.proto == "tcp"
    assert rule.dst_port == "80"
    assert rule.content == b"GET /"
    assert rule.nocase is True
    assert rule.severity == "high"


def test_parse_threshold_clause():
    line = (
        'alert tcp any any -> any 22 (msg:"ssh"; flags:S; '
        "threshold: type threshold, track by_src, count 5, seconds 60; sid:2;)"
    )
    rule = parse_rule(line)
    assert rule.threshold.type == "threshold"
    assert rule.threshold.track == "by_src"
    assert rule.threshold.count == 5
    assert rule.threshold.seconds == 60.0


def test_parse_dsize_clause():
    line = 'alert icmp any any -> any any (msg:"big icmp"; dsize:>800; sid:3;)'
    rule = parse_rule(line)
    assert rule.dsize.op == ">"
    assert rule.dsize.value == 800


def test_parse_ignores_blank_lines_and_comments():
    assert parse_rule("") is None
    assert parse_rule("   ") is None
    assert parse_rule("# a comment") is None


def test_parse_requires_sid():
    with pytest.raises(RuleParseError):
        parse_rule('alert tcp any any -> any 80 (msg:"no sid";)')


def test_parse_malformed_header_raises():
    with pytest.raises(RuleParseError):
        parse_rule("not a valid rule at all")


def test_parse_file(tmp_path):
    path = tmp_path / "test.rules"
    path.write_text(
        "# comment\n"
        'alert tcp any any -> any 80 (msg:"one"; sid:100;)\n'
        "\n"
        'alert udp any any -> any 53 (msg:"two"; sid:101;)\n'
    )
    rules = parse_file(path)
    assert [r.sid for r in rules] == [100, 101]


def test_parse_dir_loads_all_rules_files(tmp_path):
    (tmp_path / "a.rules").write_text('alert tcp any any -> any 80 (msg:"a"; sid:200;)\n')
    (tmp_path / "b.rules").write_text('alert tcp any any -> any 81 (msg:"b"; sid:201;)\n')
    (tmp_path / "ignored.txt").write_text('alert tcp any any -> any 82 (msg:"c"; sid:202;)\n')
    rules = parse_dir(tmp_path)
    assert [r.sid for r in rules] == [200, 201]


def test_builtin_default_rules_all_parse():
    rules = parse_dir("rules/builtin")
    assert len(rules) >= 10
    sids = [r.sid for r in rules]
    assert len(sids) == len(set(sids))  # no duplicate sids
