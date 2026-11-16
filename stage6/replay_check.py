#!/usr/bin/env python3
"""Offline sanity check: replay recorded feature CSVs through scorer.py's Model + Trust.

Normal baseline should stay trusted (~1% anomalous windows); each labeled attack
should drive the device to isolated. No root, no capture, no nftables.
"""

import csv, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scorer as sc  # noqa: E402

DATA = sc.ROOT / "data"
LABELS = sc.ROOT / "attacks" / "labels.csv"


def rows(path):
    with open(path) as fh:
        for r in csv.DictReader(fh):
            yield {k: (v if k in ("mac", "device_class") else float(v)) for k, v in r.items()}


def main():
    model = sc.Model(sc.ROOT / "ml")
    print(f"threshold {model.threshold:.3f}\n")

    trust = sc.Trust(30, 2)
    n = anom = lat = 0
    worst = 100.0
    for r in rows(DATA / "baseline_normal.csv"):
        score, _, l = model.score(model.vector(r))
        t = trust.update(r["mac"], score > model.threshold)
        n += 1; anom += score > model.threshold; lat += l; worst = min(worst, t)
    print(f"baseline: {n} windows, {anom} anomalous ({anom / n:.2%}), lowest trust {worst:.0f} "
          f"({sc.trust_state(worst)}), avg latency {lat / n:.0f}µs")

    labels = list(csv.DictReader(open(LABELS)))
    atk = list(rows(DATA / "attacks.csv"))
    for lab in labels:
        start, end = float(lab["start"]), float(lab["end"])
        trust = sc.Trust(30, 2)
        # warm-up: the normal windows just before the attack, then the attack windows
        window = [r for r in atk if start - 120 <= r["ts"] <= end + 10]
        path, low = [], 100.0
        for r in window:
            score, _, _ = model.score(model.vector(r))
            t = trust.update(r["mac"], score > model.threshold)
            if r["ts"] >= start:
                low = min(low, t)
                path.append(f"{score:.1f}->{t:.0f}")
        print(f"{lab['label']:11s} lowest {sc.trust_state(low):10s} {' '.join(path)}")


if __name__ == "__main__":
    main()
