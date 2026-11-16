#!/usr/bin/env python3
"""Stage 6: read-only dashboard API over the scorer's state.db."""

import json, sqlite3
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

HERE = Path(__file__).resolve().parent
DB_PATH = HERE / "state.db"
EVENTS_SHOWN = 100

app = Flask(__name__)


def query(db, sql, *params):
    return [dict(r) for r in db.execute(sql, params)]


@app.get("/")
def index():
    return send_from_directory(HERE, "dashboard.html")


@app.get("/api/state")
def state():
    if not DB_PATH.exists():
        return jsonify(error="state.db not found - is scorer.py running?"), 503
    db = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2)
    db.row_factory = sqlite3.Row
    try:
        meta = {r["key"]: json.loads(r["value"]) for r in db.execute("SELECT key, value FROM meta")}
        devices = query(db, "SELECT * FROM devices ORDER BY mac")
        scores = query(db, "SELECT ts, mac, score FROM scores ORDER BY id")
        events = query(db, "SELECT ts, mac, kind, message, detail FROM events ORDER BY id DESC LIMIT ?",
                       EVENTS_SHOWN)
    finally:
        db.close()
    for e in events:
        e["detail"] = json.loads(e["detail"]) if e["detail"] else None
    return jsonify(
        devices=devices,
        scores=scores,
        events=events,
        totals={
            "devices": len(devices),
            "windows_scored": meta.get("windows_scored", 0),
            "quarantines": meta.get("quarantines", 0),
            "avg_latency_us": meta.get("avg_latency_us"),
            "threshold": meta.get("threshold"),
        },
        gateway={k: meta.get(k) for k in ("hostname", "gateway_ip", "iface", "mode", "window_s",
                                          "started_at", "updated_at")},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
