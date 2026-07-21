import json

import responses

from alerts.console_sink import make_console_sink
from alerts.email_sink import make_email_sink
from alerts.log_sink import make_log_sink
from alerts.webhook_sink import make_webhook_sink
from core.config import AlertConfig
from core.models import Alert


def _alert():
    return Alert(kind="port_scan", severity="high", src="10.0.0.5", dst="10.0.0.1", detail="detail", ts=1234.5, sid=1000010, score=3.0)


def test_log_sink_appends_jsonl(tmp_path):
    path = tmp_path / "alerts.jsonl"
    sink = make_log_sink(str(path))
    sink(_alert())
    sink(_alert())
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    row = json.loads(lines[0])
    assert row["kind"] == "port_scan"
    assert row["sid"] == 1000010


def test_console_sink_writes_plain_text_when_not_a_tty(capsys):
    import io

    stream = io.StringIO()
    stream.isatty = lambda: False
    sink = make_console_sink(stream)
    sink(_alert())
    output = stream.getvalue()
    assert "HIGH" in output
    assert "port_scan" in output
    assert "\x1b[" not in output


def test_console_sink_colors_when_tty():
    import io

    stream = io.StringIO()
    stream.isatty = lambda: True
    sink = make_console_sink(stream)
    sink(_alert())
    assert "\x1b[" in stream.getvalue()


def test_email_sink_is_none_when_unconfigured():
    assert make_email_sink(AlertConfig()) is None


def test_email_sink_sends_via_smtplib(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, user, password):
            sent["login"] = (user, password)

        def send_message(self, msg):
            sent["message"] = msg

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)

    config = AlertConfig(
        smtp_host="smtp.example.test",
        smtp_port=587,
        smtp_user="alerts",
        smtp_password="secret",
        email_from="mini-ids@example.test",
        email_to=["soc@example.test"],
    )
    sink = make_email_sink(config)
    assert sink is not None
    sink(_alert())

    assert sent["host"] == "smtp.example.test"
    assert sent["tls"] is True
    assert sent["login"] == ("alerts", "secret")
    assert sent["message"]["To"] == "soc@example.test"


def test_webhook_sink_is_none_when_unconfigured():
    assert make_webhook_sink(AlertConfig()) is None


@responses.activate
def test_webhook_sink_posts_json():
    responses.add(responses.POST, "https://hooks.example.test/mini-ids", json={"ok": True}, status=200)
    config = AlertConfig(webhook_url="https://hooks.example.test/mini-ids")
    sink = make_webhook_sink(config)
    assert sink is not None
    sink(_alert())

    assert len(responses.calls) == 1
    body = json.loads(responses.calls[0].request.body)
    assert body["kind"] == "port_scan"
    assert body["sid"] == 1000010
