"""Thread-safe SQLite persistence for alerts and completed flows.

One lock wraps every read/write since the capture thread and the dashboard's
Flask/Socket.IO thread share one store (``check_same_thread=False``).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from core.models import Alert, Flow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    src TEXT,
    dst TEXT,
    sid INTEGER,
    score REAL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_kind ON alerts(kind);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proto TEXT,
    src TEXT,
    sport INTEGER,
    dst TEXT,
    dport INTEGER,
    packet_count INTEGER,
    byte_count INTEGER,
    start_ts REAL,
    last_ts REAL,
    flags_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src, last_ts);
"""


class IDSStore:
    def __init__(self, db_path: str = "data/mini_ids.db"):
        path = Path(db_path)
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def log_alert(self, alert: Alert) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts (ts, kind, severity, src, dst, sid, score, detail) VALUES (?,?,?,?,?,?,?,?)",
                (alert.ts, alert.kind, alert.severity, alert.src, alert.dst, alert.sid, alert.score, alert.detail),
            )
            self._conn.commit()

    def log_flow(self, flow: Flow) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO flows (proto, src, sport, dst, dport, packet_count, byte_count, start_ts, last_ts, flags_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    flow.proto,
                    flow.src,
                    flow.sport,
                    flow.dst,
                    flow.dport,
                    flow.packet_count,
                    flow.byte_count,
                    flow.start_ts,
                    flow.last_ts,
                    json.dumps(sorted(flow.flags_seen)),
                ),
            )
            self._conn.commit()

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT ts, kind, severity, src, dst, sid, score, detail FROM alerts ORDER BY ts DESC LIMIT ?",
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def recent_flows(self, limit: int = 100) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT proto, src, sport, dst, dport, packet_count, byte_count, start_ts, last_ts FROM flows "
                "ORDER BY last_ts DESC LIMIT ?",
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def stats(self) -> dict:
        with self._lock:
            total_alerts = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_kind = dict(self._conn.execute("SELECT kind, COUNT(*) FROM alerts GROUP BY kind").fetchall())
            by_severity = dict(self._conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            total_flows = self._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            top_src = self._conn.execute(
                "SELECT src, COUNT(*) as c FROM alerts GROUP BY src ORDER BY c DESC LIMIT 10"
            ).fetchall()
            return {
                "total_alerts": total_alerts,
                "alerts_by_kind": by_kind,
                "alerts_by_severity": by_severity,
                "total_flows": total_flows,
                "top_sources": [{"src": s, "count": c} for s, c in top_src],
            }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
