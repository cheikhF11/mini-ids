"""Webhook alert sink (plain HTTP POST). No-op if no URL is configured."""

from __future__ import annotations

from typing import Callable, Optional

from core.config import AlertConfig
from core.models import Alert


def make_webhook_sink(config: AlertConfig) -> Optional[Callable[[Alert], None]]:
    if not config.webhook_url:
        return None

    def sink(alert: Alert) -> None:
        import requests

        requests.post(config.webhook_url, json=alert.to_dict(), timeout=config.webhook_timeout)

    return sink
