"""JSONL append-only alert log - easy to grep or ship to a SIEM."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable

from core.models import Alert


def make_log_sink(path: str) -> Callable[[Alert], None]:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def sink(alert: Alert) -> None:
        with lock:
            with open(p, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")

    return sink
