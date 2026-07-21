from core.config import AlertConfig
from core.models import Alert
from alerts.dispatcher import AlertDispatcher


def _alert(kind="port_scan", src="10.0.0.5", dst="", sid=None, ts=0.0):
    return Alert(kind=kind, severity="high", src=src, dst=dst, detail="detail", ts=ts, sid=sid)


def test_dispatch_calls_all_sinks():
    received = []
    dispatcher = AlertDispatcher(AlertConfig(default_cooldown=0.0), sinks=[received.append, received.append])
    ok = dispatcher.dispatch(_alert(), now=0.0)
    assert ok is True
    assert len(received) == 2


def test_dispatch_respects_cooldown_per_key():
    received = []
    dispatcher = AlertDispatcher(AlertConfig(default_cooldown=30.0), sinks=[received.append])
    assert dispatcher.dispatch(_alert(ts=0.0), now=0.0) is True
    assert dispatcher.dispatch(_alert(ts=1.0), now=1.0) is False
    assert len(received) == 1


def test_dispatch_different_keys_are_independent():
    received = []
    dispatcher = AlertDispatcher(AlertConfig(default_cooldown=30.0), sinks=[received.append])
    assert dispatcher.dispatch(_alert(src="10.0.0.1"), now=0.0) is True
    assert dispatcher.dispatch(_alert(src="10.0.0.2"), now=0.1) is True
    assert len(received) == 2


def test_dispatch_cooldown_expires():
    received = []
    dispatcher = AlertDispatcher(AlertConfig(default_cooldown=5.0), sinks=[received.append])
    assert dispatcher.dispatch(_alert(ts=0.0), now=0.0) is True
    assert dispatcher.dispatch(_alert(ts=10.0), now=10.0) is True
    assert len(received) == 2


def test_a_broken_sink_never_blocks_the_others():
    received = []

    def broken(alert):
        raise RuntimeError("sink is down")

    errors = []
    dispatcher = AlertDispatcher(
        AlertConfig(default_cooldown=0.0),
        sinks=[broken, received.append],
        on_error=lambda sink, exc: errors.append(exc),
    )
    ok = dispatcher.dispatch(_alert(), now=0.0)
    assert ok is True
    assert len(received) == 1
    assert len(errors) == 1


def test_register_ignores_none():
    dispatcher = AlertDispatcher()
    dispatcher.register(None)
    assert dispatcher.sinks == []
