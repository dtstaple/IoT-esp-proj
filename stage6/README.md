# Stage 6 — live anomaly scoring, trust, quarantine

**Modes:** by default the scorer is **detect-only**: it scores traffic and logs `WOULD quarantine …` without touching nftables. `--enforce` actually removes the MAC from `inet filter enrolled` and flushes its conntrack entries.

## Files

| file | role |
|---|---|
| `scorer.py` | root daemon: sniffs `wlan0`, 10 s windows via `capture/capture.py`'s own `on_packet`/`extract_features`, ONNX autoencoder score, trust tracking, quarantine |
| `app.py` | Flask, `0.0.0.0:5000`, read-only over `state.db`; `GET /api/state`, `/` → dashboard |
| `dashboard.html` | single-file console, polls `/api/state` every 2 s |
| `state.db` | SQLite written by the scorer, wiped at each scorer start |

## Run

```bash
cd ~/ztgw

# 1. scorer (needs root for capture); detect-only first
sudo ~/ztgw/.venv/bin/python stage6/scorer.py

# ...once the scores look right, arm it
sudo ~/ztgw/.venv/bin/python stage6/scorer.py --enforce

# 2. dashboard (second terminal, no sudo)
~/ztgw/.venv/bin/python stage6/app.py
# -> http://zt-gateway.local:5000  (or http://10.42.0.1:5000 from the IoT LAN)
```

Options: `--model-dir` (default `~/ztgw/ml`), `--penalty 30`, `--recovery 2`, `--iface wlan0`, `--db`.

The model needs `ml/model_autoencoder.onnx` **and** `ml/model_autoencoder.onnx.data` (the exporter put the weights in the second file).

## Scoring and trust

- Features: the 21 numeric columns of `capture.FIELDS`, in `model_meta.json` order (the scorer refuses to start if they differ). Scaled with `scaler_mean`/`scaler_scale`; score = mean squared reconstruction error; anomalous when `score > ae_threshold` (≈ 7.89).
- Trust starts at 100; an anomalous window costs **30**, a normal window gives back **2**. State: ≥ 80 trusted, 50–79 restricted, < 50 isolated.
  - Two anomalous windows in a row (100 → 70 → 40) isolate a device, so one ~1%-rate false positive only restricts it.
  - Recovery from 70 back to trusted takes 5 normal windows (~50 s).
- On entering isolated: `nft delete element inet filter enrolled { <mac> }` then `conntrack -D -s <ip>` (IP from `/var/lib/misc/dnsmasq.leases`). The full feature vector that triggered it is logged as a `trigger_vector` event.
- In `--enforce` mode isolation **latches**: the device stays isolated until you re-enroll it and restart the scorer. In detect-only mode the state follows trust freely.

## Re-enroll a quarantined device

```bash
sudo nft add element inet filter enrolled '{ f0:16:1d:51:4d:34 }'
# then restart the scorer (Ctrl-C, re-run) to reset its trust
```

## Known gap: quarantine does not cut MQTT

`enrolled` is only checked in the **forward** chain. The ESP32 publishes to the broker on the Pi itself, which goes through the **input** chain, and that chain has `iif "wlan0" tcp dport 8883 accept` with no enrollment check. So with the current ruleset a quarantined device loses routed/internet access, but its MQTT session survives the conntrack flush (mid-stream packets still match the port rule) and it can reconnect. To make quarantine cut the broker too, gate that rule on the set:

```
iif "wlan0" ether saddr @enrolled tcp dport 8883 accept
```

With that change the existing session's packets fall through to `policy drop` once conntrack is flushed. If you also want DHCP/DNS to keep working for re-enrollment, leave the `udp dport { 53, 67 }` rule ungated.
