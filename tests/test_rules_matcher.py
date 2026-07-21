from core.models import PacketRecord
from rules.matcher import RuleMatcher
from rules.parser import parse_rule


def _pkt(**kwargs):
    defaults = dict(no=0, ts=0.0, length=60, proto="TCP", src="10.0.0.5", dst="10.0.0.1", sport=1234, dport=80, tcp_flags="S")
    defaults.update(kwargs)
    return PacketRecord(**defaults)


def test_content_match_is_case_sensitive_without_nocase():
    rule = parse_rule('alert tcp any any -> any 80 (msg:"m"; content:"GET"; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(payload=b"GET /x", dport=80), now=0.0)
    assert not matcher.match(_pkt(payload=b"get /x", dport=80), now=0.0)


def test_content_match_nocase():
    rule = parse_rule('alert tcp any any -> any 80 (msg:"m"; content:"get"; nocase; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(payload=b"GET /x", dport=80), now=0.0)


def test_flags_null_scan():
    rule = parse_rule('alert tcp any any -> any any (msg:"null"; flags:0; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(tcp_flags=""), now=0.0)
    assert not matcher.match(_pkt(tcp_flags="S"), now=0.0)


def test_flags_exact_match():
    rule = parse_rule('alert tcp any any -> any any (msg:"xmas"; flags:=FPU; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(tcp_flags="FPU"), now=0.0)
    assert not matcher.match(_pkt(tcp_flags="FPUS"), now=0.0)  # extra flag breaks exact match


def test_flags_at_least_match():
    rule = parse_rule('alert tcp any any -> any any (msg:"syn"; flags:S; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(tcp_flags="S"), now=0.0)
    assert matcher.match(_pkt(tcp_flags="SA"), now=0.0)  # SYN present, ACK also set - still matches
    assert not matcher.match(_pkt(tcp_flags="A"), now=0.0)


def test_dsize_match():
    rule = parse_rule('alert icmp any any -> any any (msg:"big"; dsize:>10; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(proto="ICMP", payload=b"0123456789ABCDEF"), now=0.0)
    assert not matcher.match(_pkt(proto="ICMP", payload=b"short"), now=0.0)


def test_cidr_ip_match():
    rule = parse_rule('alert tcp any any -> 10.0.0.0/24 22 (msg:"m"; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(dst="10.0.0.55", dport=22), now=0.0)
    assert not matcher.match(_pkt(dst="192.168.1.1", dport=22), now=0.0)


def test_threshold_fires_only_after_count_reached_and_then_resets():
    rule = parse_rule(
        'alert tcp any any -> any 22 (msg:"brute"; flags:S; '
        "threshold: type threshold, track by_src, count 3, seconds 60; sid:1;)"
    )
    matcher = RuleMatcher([rule])
    now = 1000.0
    results = [matcher.match(_pkt(dport=22), now=now + i) for i in range(3)]
    assert results[0] == [] and results[1] == []
    assert len(results[2]) == 1  # fires exactly on the 3rd attempt

    # counter reset after firing - next 2 attempts alone should not re-fire
    results_after = [matcher.match(_pkt(dport=22), now=now + 10 + i) for i in range(2)]
    assert results_after == [[], []]


def test_threshold_window_expires_old_events():
    rule = parse_rule(
        'alert tcp any any -> any 22 (msg:"brute"; flags:S; '
        "threshold: type threshold, track by_src, count 3, seconds 5; sid:1;)"
    )
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(dport=22), now=0.0) == []
    assert matcher.match(_pkt(dport=22), now=1.0) == []
    # this event is outside the 5s window relative to the first two - should not combine with them
    assert matcher.match(_pkt(dport=22), now=100.0) == []


def test_threshold_tracks_by_dst():
    rule = parse_rule(
        'alert tcp any any -> any any (msg:"fanin"; flags:S; '
        "threshold: type threshold, track by_dst, count 2, seconds 60; sid:1;)"
    )
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(src="10.0.0.1", dst="10.0.0.99"), now=0.0) == []
    result = matcher.match(_pkt(src="10.0.0.2", dst="10.0.0.99"), now=1.0)
    assert len(result) == 1  # two different sources hitting the same dst within window


def test_no_match_wrong_proto():
    rule = parse_rule('alert udp any any -> any 53 (msg:"m"; sid:1;)')
    matcher = RuleMatcher([rule])
    assert matcher.match(_pkt(proto="TCP", dport=53), now=0.0) == []
