from core.config import ExfilConfig
from core.models import PacketRecord
from detectors.exfil import ExfilDetector, shannon_entropy, split_domain


def _query(qname, qtype="TXT", ts=0.0, src="10.0.0.5"):
    return PacketRecord(no=0, ts=ts, length=60, proto="DNS", src=src, dst="10.0.0.53", dns_qr=0, dns_qname=qname, dns_qtype=qtype)


def test_split_domain_takes_last_two_labels():
    sld, subs = split_domain("a.b.evil.test")
    assert sld == "evil.test"
    assert subs == ["a", "b"]


def test_shannon_entropy_of_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_higher_for_random_than_repeated():
    assert shannon_entropy("aaaaaaaaaa") < shannon_entropy("qwj93kslpz")


def test_encoded_label_triggers_alert():
    cfg = ExfilConfig(max_label_length=20, entropy_threshold=3.0)
    detector = ExfilDetector(cfg)
    long_random_label = "kq7z2mplsx9vbtaewrfy4hj0"
    alert = detector.observe(_query(f"{long_random_label}.tunnel.evil.test"), now=0.0)
    assert alert is not None
    assert alert.kind == "exfil"
    assert alert.dst == "evil.test"  # sld is approximated as the last two labels


def test_long_but_real_hostname_does_not_trigger():
    cfg = ExfilConfig(max_label_length=30, entropy_threshold=3.5)
    detector = ExfilDetector(cfg)
    alert = detector.observe(_query("static-cdn-assets-eu-west-1.cloudfront-benign.test"), now=0.0)
    assert alert is None


def test_subdomain_fanout_triggers_alert():
    cfg = ExfilConfig(unique_subdomains=5, max_label_length=100, entropy_threshold=100.0)
    detector = ExfilDetector(cfg)
    for i in range(6):
        alert = detector.observe(_query(f"sub{i}.fanout.test"), now=float(i))
    assert alert is not None
    assert "subdomain-fanout" in alert.detail


def test_responses_are_ignored():
    detector = ExfilDetector()
    alert = detector.observe(_query("anything.test", ts=0.0), now=0.0)
    response = PacketRecord(no=0, ts=1.0, length=60, proto="DNS", dns_qr=1, dns_qname="anything.test")
    assert detector.observe(response, now=1.0) is None


def test_cooldown_suppresses_repeat_alerts_for_same_domain():
    cfg = ExfilConfig(max_label_length=5, entropy_threshold=1.0, cooldown=60.0)
    detector = ExfilDetector(cfg)
    label = "kq7z2mplsx9vbtaewrfy4hj0"
    first = detector.observe(_query(f"{label}.tunnel.evil.test"), now=0.0)
    second = detector.observe(_query(f"{label}b.tunnel.evil.test"), now=1.0)
    assert first is not None
    assert second is None
