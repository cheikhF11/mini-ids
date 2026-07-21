"""Central alert bus: cooldown/anti-spam gate, fanned out to registered sinks.

Detectors already keep their own per-key cooldowns; this dispatcher is a
second, coarser safety net (keyed on kind/src/dst/sid) so that wiring several
detectors together can never flood the sinks. Sinks are plain callables and
are always called fail-soft - one broken sink (SMTP down, webhook host
unreachable) must never crash the engine or block the others.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from core.config import AlertConfig
from core.models import Alert


class AlertDispatcher:
    def __init__(
        self,
        config: Optional[AlertConfig] = None,
        sinks: Optional[list[Callable[[Alert], None]]] = None,
        clock: Callable[[], float] = time.time,
        on_error: Optional[Callable[[Callable, Exception], None]] = None,
    ):
        self.cfg = config or AlertConfig()
        self.sinks: list[Callable[[Alert], None]] = list(sinks or [])
        self._clock = clock
        self._on_error = on_error
        self._last: dict[tuple, float] = {}

    def register(self, sink: Optional[Callable[[Alert], None]]) -> None:
        if sink is not None:
            self.sinks.append(sink)

    def dispatch(self, alert: Alert, now: Optional[float] = None) -> bool:
        """Fan ``alert`` out to every sink, subject to the cooldown gate.

        Returns True if the alert passed the cooldown gate and was sent to
        sinks (even if every sink then failed), False if it was suppressed.
        """
        now = now if now is not None else self._clock()
        key = (alert.kind, alert.src, alert.dst, alert.sid)
        last = self._last.get(key)
        if last is not None and now - last < self.cfg.default_cooldown:
            return False
        self._last[key] = now

        for sink in self.sinks:
            try:
                sink(alert)
            except Exception as exc:  # sinks must never take the engine down
                if self._on_error is not None:
                    self._on_error(sink, exc)
        return True
