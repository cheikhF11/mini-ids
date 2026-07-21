"""ANSI-colored stderr alert sink, colored by severity."""

from __future__ import annotations

import sys
from typing import Callable, TextIO

from core.models import Alert

_COLORS = {"low": "36", "medium": "33", "high": "31", "critical": "35"}


def make_console_sink(stream: TextIO = sys.stderr) -> Callable[[Alert], None]:
    def sink(alert: Alert) -> None:
        text = f"[{alert.severity.upper()}] {alert.kind}: {alert.detail}"
        if getattr(stream, "isatty", lambda: False)():
            color = _COLORS.get(alert.severity, "37")
            text = f"\x1b[{color}m{text}\x1b[0m"
        print(text, file=stream)

    return sink
