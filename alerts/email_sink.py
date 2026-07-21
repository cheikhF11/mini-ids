"""SMTP email alert sink. Returns ``None`` (no-op) if unconfigured, so wiring
code can filter it out of the sink list instead of registering a dead sink.
"""

from __future__ import annotations

from typing import Callable, Optional

from core.config import AlertConfig
from core.models import Alert


def make_email_sink(config: AlertConfig) -> Optional[Callable[[Alert], None]]:
    if not config.smtp_host or not config.email_to or not config.email_from:
        return None

    def sink(alert: Alert) -> None:
        import smtplib
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["Subject"] = f"[mini-ids] {alert.severity.upper()} {alert.kind} alert"
        msg["From"] = config.email_from
        msg["To"] = ", ".join(config.email_to)
        msg.set_content(
            f"{alert.kind} ({alert.severity}) from {alert.src} to {alert.dst}\n{alert.detail}\nts={alert.ts}"
        )
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as server:
            if config.smtp_use_tls:
                server.starttls()
            if config.smtp_user and config.smtp_password:
                server.login(config.smtp_user, config.smtp_password)
            server.send_message(msg)

    return sink
