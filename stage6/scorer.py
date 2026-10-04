#!/usr/bin/env python3
"""Stage 6: live anomaly scoring + trust-based quarantine for the ZT gateway.

Captures 10s per-device windows with capture.py's own extractor, scores them
with the Stage 5 autoencoder (ONNX), and maintains a per-device trust score.
Default is detect-only; pass --enforce to actually quarantine via nftables.
"""

import argparse, json, os, re, signal, socket, sqlite3, subprocess, sys, threading, time
from pathlib import Path

import numpy as np
import onnxruntime as ort

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "capture"))
import capture as cap  # noqa: E402  -- shared feature extraction, no reimplementation

DB_PATH = ROOT / "stage6" / "state.db"
LEASES = "/var/lib/misc/dnsmasq.leases"
MOSQ_LOG = "/var/log/mosquitto/mosquitto.log"
NFT_SET = ("inet", "filter", "enrolled")
SCORES_KEPT = 200

TRUST_MAX = 100.0
TRUSTED_MIN, RESTRICTED_MIN = 80, 50


def trust_state(trust):
    if trust >= TRUSTED_MIN:
        return "trusted"
    if trust >= RESTRICTED_MIN:
        return "restricted"
    return "isolated"


# ---------- model ----------

class Model:
    def __init__(self, model_dir):
        model_dir = Path(model_dir)
        meta = json.loads((model_dir / "model_meta.json").read_text())
        self.features = meta["features"]
        expected = [f for f in cap.FIELDS if f not in ("ts", "mac", "device_class")]
        if self.features != expected:
            raise SystemExit(f"feature mismatch between model_meta.json and capture.FIELDS:\n"
                             f"  model:   {self.features}\n  capture: {expected}")
        self.threshold = float(meta["ae_threshold"])
        # StandardScaler.transform == (x - mean_) / scale_; meta carries both verbatim
        self.mean = np.asarray(meta["scaler_mean"], dtype=np.float64)
        self.scale = np.asarray(meta["scaler_scale"], dtype=np.float64)
        self.sess = ort.InferenceSession(str(model_dir / "model_autoencoder.onnx"),
                                         providers=["CPUExecutionProvider"])
        self.input_name = self.sess.get_inputs()[0].name

    def vector(self, row):
        return np.array([row[f] for f in self.features], dtype=np.float64)

    def score(self, raw):
        """Return (mse, per-feature squared error, inference latency in µs)."""
        x = ((raw - self.mean) / self.scale).astype(np.float32).reshape(1, -1)
        t0 = time.perf_counter()
        recon = self.sess.run(None, {self.input_name: x})[0]
        latency_us = (time.perf_counter() - t0) * 1e6
        err = (recon[0] - x[0]) ** 2
        return float(err.mean()), err, latency_us


# ---------- trust ----------

class Trust:
    """Asymmetric decay: drop fast on anomalies, heal slowly on normal windows."""

    def __init__(self, penalty, recovery):
        self.penalty, self.recovery = penalty, recovery
        self.trust = {}

    def update(self, mac, anomalous):
        t = self.trust.get(mac, TRUST_MAX)
        t = max(0.0, t - self.penalty) if anomalous else min(TRUST_MAX, t + self.recovery)
        self.trust[mac] = t
        return t


# ---------- host lookups ----------

def lease_ip(mac):
    try:
        with open(LEASES) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1].lower() == mac:
                    return parts[2]
    except OSError:
        pass
    return None


CONNECT_RE = re.compile(r"New client connected from ([\d.]+):\d+ as (\S+).*?u'([^']*)'")


def cert_status(ip):
    """Latest mTLS state for ip from mosquitto's log (use_identity_as_username => u'<CN>')."""
    if not ip:
        return "unknown"
    try:
        with open(MOSQ_LOG, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 256 * 1024))
            lines = fh.read().decode(errors="replace").splitlines()
    except OSError:
        return "unknown"
    client = cn = None
    connected = False
    for line in lines:
        m = CONNECT_RE.search(line)
        if m and m.group(1) == ip:
            client, cn, connected = m.group(2), m.group(3), True
        elif connected and f"Client {client} " in line and (
                "disconnected" in line or "closed its connection" in line or "exceeded timeout" in line):
            connected = False
    if cn is None:
        return "unknown"
    return f"{'valid' if connected else 'disconnected'} · CN={cn}"


# ---------- persistence ----------

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, ip TEXT, device_class TEXT, trust REAL, state TEXT,
    cert_status TEXT, last_seen REAL, last_score REAL, quarantined INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, mac TEXT, score REAL);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, mac TEXT, kind TEXT, message TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.executescript(SCHEMA)
        # state is per-run: start every session from a clean slate
        self.db.executescript("DELETE FROM devices; DELETE FROM scores; DELETE FROM events; DELETE FROM meta;")
        self.db.commit()
        # scorer runs as root; hand the file to the invoking user so Flask can read it
        uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if uid and gid:
            os.chown(self.path, int(uid), int(gid))

    def set_meta(self, **kv):
        self.db.executemany("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                            [(k, json.dumps(v)) for k, v in kv.items()])

    def event(self, mac, kind, message, detail=None):
        ts = time.time()
        self.db.execute("INSERT INTO events (ts, mac, kind, message, detail) VALUES (?, ?, ?, ?, ?)",
                        (ts, mac, kind, message, json.dumps(detail) if detail is not None else None))
        print(f"[{time.strftime('%H:%M:%S', time.localtime(ts))}] {kind:16s} {mac or '-':17s} {message}",
              flush=True)

    def device(self, **d):
        self.db.execute(
            "INSERT OR REPLACE INTO devices (mac, ip, device_class, trust, state, cert_status,"
            " last_seen, last_score, quarantined) VALUES (:mac, :ip, :device_class, :trust, :state,"
            " :cert_status, :last_seen, :last_score, :quarantined)", d)

    def score(self, ts, mac, score):
        self.db.execute("INSERT INTO scores (ts, mac, score) VALUES (?, ?, ?)", (ts, mac, score))
        self.db.execute("DELETE FROM scores WHERE id <= (SELECT MAX(id) FROM scores) - ?", (SCORES_KEPT,))

    def commit(self):
        self.db.commit()

    def close(self):
        self.db.commit()
        self.db.close()


# ---------- enforcement ----------

def quarantine_cmds(mac, ip):
    cmds = [["nft", "delete", "element", *NFT_SET, f"{{ {mac} }}"]]
    if ip:
        # established flows match `ct state established,related accept` before the
        # allowlist, so the set delete alone does not cut live connections
        cmds.append(["conntrack", "-D", "-s", ip])
    return cmds


def run_cmd(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout + p.stderr).strip().splitlines()
    return p.returncode, out[-1] if out else ""


# ---------- main loop ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--enforce", action="store_true",
                    help="actually quarantine via nft + conntrack (default: detect-only)")
    ap.add_argument("--iface", default=cap.IFACE)
    ap.add_argument("--model-dir", default=str(ROOT / "ml"))
    ap.add_argument("--db", default=str(DB_PATH))
    ap.add_argument("--penalty", type=float, default=30.0, help="trust lost per anomalous window")
    ap.add_argument("--recovery", type=float, default=2.0, help="trust regained per normal window")
    args = ap.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("packet capture needs root: sudo ~/ztgw/.venv/bin/python stage6/scorer.py")

    model = Model(args.model_dir)
    trust = Trust(args.penalty, args.recovery)
    store = Store(args.db)
    mode = "enforce" if args.enforce else "detect-only"
    windows_scored, latency_sum = 0, 0.0
    quarantined = set()
    last_state = {}
    ips = {}

    store.set_meta(mode=mode, threshold=model.threshold, iface=args.iface, gateway_ip=cap.GATEWAY_IP,
                   hostname=socket.gethostname(), window_s=cap.WINDOW_S, started_at=time.time(),
                   windows_scored=0, avg_latency_us=None, quarantines=0)
    store.event(None, "start", f"scorer started on {args.iface} in {mode} mode, "
                               f"threshold {model.threshold:.3f}")
    store.commit()

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    sniffer = cap.AsyncSniffer(iface=args.iface, prn=cap.on_packet, store=False)
    sniffer.start()

    next_tick = time.time() + cap.WINDOW_S
    while not stop.wait(max(0.0, next_tick - time.time())):
        next_tick += cap.WINDOW_S
        now = time.time()
        for mac in list(cap.DEVICE_CLASS):
            row = cap.extract_features(mac, cap.windows.pop(mac, cap.Window()), now)
            raw = model.vector(row)
            score, err, lat = model.score(raw)
            anomalous = score > model.threshold
            windows_scored += 1
            latency_sum += lat

            t = trust.update(mac, anomalous)
            state = "isolated" if mac in quarantined else trust_state(t)
            prev = last_state.get(mac, "trusted")
            ip = lease_ip(mac) or ips.get(mac)
            ips[mac] = ip

            if anomalous:
                top = sorted(zip(model.features, err.tolist()), key=lambda p: -p[1])[:3]
                store.event(mac, "anomaly",
                            f"score {score:.2f} > {model.threshold:.2f} · trust {t:.0f} · "
                            + ", ".join(f"{f}={row[f]}" for f, _ in top))

            if state != prev and mac not in quarantined:
                store.event(mac, f"state_{state}", f"{prev} → {state} (trust {t:.0f})")

            if state == "isolated" and prev != "isolated":
                detail = {"score": score, "trust": t, "ip": ip,
                          "features": {f: row[f] for f in model.features}}
                cmds = quarantine_cmds(mac, ip)
                shown = " && ".join(" ".join(c) for c in cmds)
                if args.enforce:
                    results = [run_cmd(c) for c in cmds]
                    detail["commands"] = [{"cmd": " ".join(c), "rc": rc, "out": out}
                                          for c, (rc, out) in zip(cmds, results)]
                    nft_rc = results[0][0]
                    quarantined.add(mac)
                    store.event(mac, "quarantine",
                                f"QUARANTINED {ip or 'ip unknown'}: {shown}"
                                + ("" if nft_rc == 0 else f" (nft rc={nft_rc}: {results[0][1]})"),
                                detail)
                else:
                    store.event(mac, "would_quarantine", f"WOULD quarantine {ip or 'ip unknown'}: {shown}",
                                detail)
                store.event(mac, "trigger_vector", json.dumps(detail["features"]))

            last_state[mac] = state
            store.score(now, mac, score)
            store.device(mac=mac, ip=ip, device_class=row["device_class"], trust=round(t, 1),
                         state=state, cert_status=cert_status(ip), last_seen=now,
                         last_score=score, quarantined=int(mac in quarantined))
            print(f"{row['device_class']:14s} score={score:8.3f} {'ANOM' if anomalous else 'ok  '} "
                  f"trust={t:5.1f} {state:10s} pkts={row['pkt_count']:4d} lat={lat:6.0f}µs", flush=True)

        n_q = store.db.execute(
            "SELECT COUNT(*) FROM events WHERE kind IN ('quarantine', 'would_quarantine')").fetchone()[0]
        store.set_meta(windows_scored=windows_scored, avg_latency_us=latency_sum / windows_scored,
                       quarantines=n_q, updated_at=now)
        store.commit()

    sniffer.stop()
    store.event(None, "stop", "scorer stopped")
    store.close()


if __name__ == "__main__":
    main()
