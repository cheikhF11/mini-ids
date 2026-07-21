"""Flask + Flask-SocketIO live dashboard.

A single background "emitter loop" drains a lock-protected buffer of pending
alerts every 250ms and pushes them over Socket.IO, mirroring the pattern used
by the sibling packet-analyzer/honeypot/netwatch dashboards - this keeps every
``socketio.emit`` call off the capture thread.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

from core.models import Alert
from rules.schema import Rule

_ROOT = Path(__file__).resolve().parent


class DashboardApp:
    def __init__(self, store=None, rules: Optional[list[Rule]] = None, auto_start: bool = True):
        self.store = store
        self.rules = rules or []
        self.app = Flask(
            __name__,
            template_folder=str(_ROOT / "templates"),
            static_folder=str(_ROOT / "static"),
        )
        self.socketio = SocketIO(self.app, async_mode="threading", cors_allowed_origins="*")
        self._lock = threading.Lock()
        self._pending_alerts: list[dict] = []
        self._setup_routes()
        if auto_start:
            self.socketio.start_background_task(self._emitter_loop)

    def on_alert(self, alert: Alert) -> None:
        with self._lock:
            self._pending_alerts.append(alert.to_dict())

    def _emitter_loop(self) -> None:
        while True:
            self.socketio.sleep(0.25)
            with self._lock:
                pending, self._pending_alerts = self._pending_alerts, []
            for item in pending:
                self.socketio.emit("alert", item)
            if pending and self.store is not None:
                self.socketio.emit("stats", self.store.stats())

    def _setup_routes(self) -> None:
        app = self.app

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/api/stats")
        def api_stats():
            return jsonify(self.store.stats() if self.store is not None else {})

        @app.route("/api/alerts")
        def api_alerts():
            limit = request.args.get("limit", 100, type=int)
            return jsonify(self.store.recent_alerts(limit) if self.store is not None else [])

        @app.route("/api/rules")
        def api_rules():
            return jsonify(
                [{"sid": r.sid, "msg": r.msg, "severity": r.severity, "proto": r.proto} for r in self.rules]
            )

        @app.route("/api/interfaces")
        def api_interfaces():
            from engine.capture import list_interfaces

            try:
                return jsonify(list_interfaces())
            except Exception:
                return jsonify([])

    def run(self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False) -> None:
        self.socketio.run(self.app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
