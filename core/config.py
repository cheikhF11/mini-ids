"""Central tunables. One dataclass per concern, composed into ``IDSConfig``.

``build_config(args)`` is the single seam that turns an argparse ``Namespace``
into this shape - the CLI and the dashboard both build the same config
through it, so there is exactly one place that knows how flags map to
behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os


@dataclass
class CaptureConfig:
    iface: str | None = None
    bpf_filter: str | None = None
    pcap_path: str | None = None


@dataclass
class RuleEngineConfig:
    rules_dir: str = "rules/builtin"


@dataclass
class PortScanConfig:
    window_seconds: float = 10.0
    port_threshold: int = 15
    cooldown: float = 30.0


@dataclass
class BruteForceConfig:
    window_seconds: float = 60.0
    attempt_threshold: int = 5
    ports: tuple[int, ...] = (21, 22, 23, 3389)
    cooldown: float = 60.0


@dataclass
class ExfilConfig:
    window_seconds: float = 60.0
    max_label_length: int = 30
    entropy_threshold: float = 3.5
    unique_subdomains: int = 15
    query_rate: int = 50
    payload_qtypes: tuple[str, ...] = ("TXT", "NULL", "CNAME")
    cooldown: float = 60.0


@dataclass
class MLConfig:
    enabled: bool = False
    contamination: float = 0.01
    model_path: str = "storage/models/isolation_forest.joblib"
    min_flow_packets: int = 2
    cooldown: float = 60.0


@dataclass
class AlertConfig:
    default_cooldown: float = 30.0
    log_path: str = "data/alerts.jsonl"
    console_enabled: bool = True
    webhook_url: str | None = None
    webhook_timeout: float = 5.0
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    email_from: str | None = None
    email_to: list[str] = field(default_factory=list)


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 5000


@dataclass
class IDSConfig:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    rules: RuleEngineConfig = field(default_factory=RuleEngineConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    exfil: ExfilConfig = field(default_factory=ExfilConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    db_path: str = "data/mini_ids.db"


def add_run_arguments(parser) -> None:
    """Shared argparse fragment for any subcommand that runs the engine."""
    parser.add_argument("--iface", default=None, help="Network interface to sniff")
    parser.add_argument("--bpf-filter", default=None, help="BPF capture filter")
    parser.add_argument("--rules-dir", default="rules/builtin", help="Directory of .rules files")
    parser.add_argument("--enable-ml", action="store_true", help="Enable the ML anomaly detector")
    parser.add_argument("--db-path", default="data/mini_ids.db", help="SQLite database path")
    parser.add_argument("--log-path", default="data/alerts.jsonl", help="JSONL alert log path")
    parser.add_argument("--webhook-url", default=os.environ.get("MINI_IDS_WEBHOOK_URL"), help="Webhook URL for alerts")
    parser.add_argument("--smtp-host", default=os.environ.get("MINI_IDS_SMTP_HOST"), help="SMTP host for email alerts")
    parser.add_argument("--smtp-port", type=int, default=int(os.environ.get("MINI_IDS_SMTP_PORT", "587")))
    parser.add_argument("--smtp-user", default=os.environ.get("MINI_IDS_SMTP_USER"))
    parser.add_argument("--smtp-password", default=os.environ.get("MINI_IDS_SMTP_PASSWORD"))
    parser.add_argument("--email-from", default=os.environ.get("MINI_IDS_EMAIL_FROM"))
    parser.add_argument("--email-to", default=os.environ.get("MINI_IDS_EMAIL_TO", ""), help="Comma-separated recipient list")
    parser.add_argument("--no-console-alerts", action="store_true", help="Disable the console alert sink")


def build_config(args) -> IDSConfig:
    email_to = [addr.strip() for addr in getattr(args, "email_to", "").split(",") if addr.strip()]
    return IDSConfig(
        capture=CaptureConfig(
            iface=getattr(args, "iface", None),
            bpf_filter=getattr(args, "bpf_filter", None),
            pcap_path=getattr(args, "pcap_path", None),
        ),
        rules=RuleEngineConfig(rules_dir=getattr(args, "rules_dir", "rules/builtin")),
        ml=MLConfig(enabled=getattr(args, "enable_ml", False)),
        alerts=AlertConfig(
            log_path=getattr(args, "log_path", "data/alerts.jsonl"),
            console_enabled=not getattr(args, "no_console_alerts", False),
            webhook_url=getattr(args, "webhook_url", None),
            smtp_host=getattr(args, "smtp_host", None),
            smtp_port=getattr(args, "smtp_port", 587),
            smtp_user=getattr(args, "smtp_user", None),
            smtp_password=getattr(args, "smtp_password", None),
            email_from=getattr(args, "email_from", None),
            email_to=email_to,
        ),
        db_path=getattr(args, "db_path", "data/mini_ids.db"),
    )
