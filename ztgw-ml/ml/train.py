#!/usr/bin/env python3
"""Stage 5: train IsolationForest + PyTorch autoencoder on normal IoT traffic,
evaluate both against labeled attacks.

Methodology:
  - one-class: both models are fit on normal traffic only
  - normal baseline is split chronologically (no shuffle) into train/val/test,
    with a purge gap at each boundary so adjacent windows don't straddle splits
  - scaler + models fit on train; threshold tuned on val; FP rate reported on
    test and on the non-attack windows of the attack session, never on val
  - attack windows come from data/attack_run_final with its own labels.csv

Run this on the PC, not the Pi (1 GB RAM is too little for torch). The Pi only
runs the exported ONNX model via stage6/scorer.py (onnxruntime, no torch).

  PC:  python -m venv .venv-train && .venv-train/bin/pip install -r ml/requirements-train.txt
       .venv-train/bin/python ml/train.py --data data      # data/ copied from the Pi
  then copy ml/{model_autoencoder.onnx,model_isoforest.joblib,scaler.joblib,model_meta.json}
  back to the Pi's ml/ directory.
"""

import argparse, hashlib, json, sys, time
from pathlib import Path

import numpy as np, pandas as pd, joblib
from scipy.stats import beta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score
try:
    import torch, torch.nn as nn
except ImportError:
    sys.exit("torch not installed. Train on the PC (see docstring); the Pi only needs onnxruntime.")

ROOT = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--data", type=Path, default=ROOT / "data",
                help="dir containing baseline_normal.csv (default: %(default)s)")
ap.add_argument("--attack-dir", type=Path, default=None,
                help="dir with features.csv + labels.csv (default: <data>/attack_run_final)")
ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent,
                help="where to write model artifacts (default: %(default)s)")
args = ap.parse_args()
DATA = args.data.resolve()
ATK_DIR = (args.attack_dir or DATA / "attack_run_final").resolve()
OUT = args.out.resolve(); OUT.mkdir(parents=True, exist_ok=True)
BASELINE = DATA / "baseline_normal.csv"
ATTACKS  = ATK_DIR / "features.csv"
LABELS   = ATK_DIR / "labels.csv"
for p in (BASELINE, ATTACKS, LABELS):
    if not p.is_file():
        sys.exit(f"missing input: {p}")
DROP = ["ts", "mac", "device_class"]
SEED = 42
WINDOW_S = 10                 # capture.py window length
SPLIT = (0.70, 0.15, 0.15)    # train / val / test, chronological
PURGE_S = 60                  # dropped at each split boundary
GUARD_S = 60                  # post-attack cooldown (attacks/run.sh) excluded from normal
FP_BUDGET_PCT = 99            # threshold = this percentile of val scores
# label `device` -> device_class in the feature CSV. Only devices whose traffic
# crosses wlan0 are visible to these features; stm32-01 sits behind the UART
# bridge on the gateway itself, so its attacks are excluded from this evaluation.
NET_DEVICES = {"esp32-01": "esp32_sensor"}
np.random.seed(SEED); torch.manual_seed(SEED)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cp_ci(k, n, alpha=0.05):
    """Clopper-Pearson exact binomial interval."""
    if n == 0:
        return (float("nan"), float("nan"))
    lo = beta.ppf(alpha / 2, k, n - k + 1) if k > 0 else 0.0
    hi = beta.ppf(1 - alpha / 2, k + 1, n - k) if k < n else 1.0
    return (float(lo), float(hi))


# ---------- load ----------
base = pd.read_csv(BASELINE).sort_values("ts").reset_index(drop=True)
atk  = pd.read_csv(ATTACKS).sort_values("ts").reset_index(drop=True)
lab  = pd.read_csv(LABELS)

FEATURES = [c for c in base.columns if c not in DROP]

# ---------- split normal chronologically: train / val / test ----------
t0, t1 = base.ts.min(), base.ts.max()
cut1 = t0 + SPLIT[0] * (t1 - t0)
cut2 = cut1 + SPLIT[1] * (t1 - t0)
train_df = base[base.ts <= cut1 - PURGE_S]
val_df   = base[(base.ts > cut1) & (base.ts <= cut2 - PURGE_S)]
test_df  = base[base.ts > cut2]

# ---------- label attack session ----------
# a row at ts aggregates packets from (ts - WINDOW_S, ts]; it is an attack window
# if that interval overlaps a labeled attack on a network-visible device
win_lo, win_hi = atk.ts - WINDOW_S, atk.ts
atk["attack_type"] = None
excluded = np.zeros(len(atk), bool)
for _, r in lab.iterrows():
    overlap = (win_hi >= r.start) & (win_lo <= r.end)
    excluded |= (win_hi >= r.start) & (win_lo <= r.end + GUARD_S)
    if r.device in NET_DEVICES:
        atk.loc[overlap & (atk.device_class == NET_DEVICES[r.device]), "attack_type"] = r.label
atk_only = atk[atk.attack_type.notna()].copy()
session_normal = atk[~excluded].copy()

print(f"normal train: {len(train_df)}  val: {len(val_df)}  test: {len(test_df)}  "
      f"(purge {PURGE_S}s at boundaries)")
print(f"attack session: {len(atk)} windows -> {len(atk_only)} attack, "
      f"{len(session_normal)} session-normal, "
      f"{len(atk) - len(atk_only) - len(session_normal)} excluded (guard band / non-network device)")
print(f"attack types: {atk_only.attack_type.value_counts().to_dict()}")
skipped = lab[~lab.device.isin(NET_DEVICES)]
print(f"excluded (not visible on wlan0): {skipped.label.tolist()}")

X_train = train_df[FEATURES].values
scaler = StandardScaler().fit(X_train)
Xtr   = scaler.transform(X_train)
Xval  = scaler.transform(val_df[FEATURES].values)
Xtest = scaler.transform(test_df[FEATURES].values)
Xsess = scaler.transform(session_normal[FEATURES].values)
Xatk  = scaler.transform(atk_only[FEATURES].values)

# ---------- Isolation Forest ----------
iso = IsolationForest(n_estimators=200, contamination=0.01, random_state=SEED)
iso.fit(Xtr)
# higher = more anomalous
iso_score = lambda X: -iso.score_samples(X)

# ---------- PyTorch autoencoder ----------
class AE(nn.Module):
    def __init__(self, d):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(d,16), nn.ReLU(), nn.Linear(16,8), nn.ReLU(), nn.Linear(8,4))
        self.dec = nn.Sequential(nn.Linear(4,8), nn.ReLU(), nn.Linear(8,16), nn.ReLU(), nn.Linear(16,d))
    def forward(self, x): return self.dec(self.enc(x))

d = Xtr.shape[1]
ae = AE(d)
opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
loss_fn = nn.MSELoss()
Xtr_t = torch.tensor(Xtr, dtype=torch.float32)

ae.train()
for epoch in range(100):
    opt.zero_grad()
    out = ae(Xtr_t)
    loss = loss_fn(out, Xtr_t)
    loss.backward(); opt.step()
    if (epoch+1) % 20 == 0:
        print(f"  ae epoch {epoch+1}: loss {loss.item():.4f}")

ae.eval()
def recon_err(Xn):
    with torch.no_grad():
        t = torch.tensor(Xn, dtype=torch.float32)
        return ((ae(t) - t)**2).mean(dim=1).numpy()

# ---------- evaluate: threshold from val, metrics on held-out data only ----------
def fp_stats(scores, thr):
    k, n = int((scores > thr).sum()), len(scores)
    lo, hi = cp_ci(k, n)
    # windows are 10s -> 360/hr
    return {"n": n, "false_pos": k, "fp_rate": k / n, "fp_rate_ci95": [lo, hi],
            "fp_per_hour": k / n * 3600 / WINDOW_S}

def evaluate(name, score_fn):
    s_val, s_test, s_sess, s_atk = (score_fn(X) for X in (Xval, Xtest, Xsess, Xatk))
    thr = float(np.percentile(s_val, FP_BUDGET_PCT))
    detected = s_atk > thr
    res = {"threshold": thr, "val_fp_rate": float((s_val > thr).mean()),
           "test_normal": fp_stats(s_test, thr), "session_normal": fp_stats(s_sess, thr),
           "per_attack": {}}
    tmp = atk_only.assign(detected=detected)
    for t, g in tmp.groupby("attack_type"):
        k, n = int(g.detected.sum()), len(g)
        res["per_attack"][t] = {"detected": k, "n": n, "rate": k / n, "ci95": list(cp_ci(k, n))}
    k, n = int(detected.sum()), len(detected)
    res["overall_detection"] = {"detected": k, "n": n, "rate": k / n, "ci95": list(cp_ci(k, n))}

    # precision/recall over attack windows vs all held-out normal (test + session)
    neg = np.concatenate([s_test, s_sess])
    tp, fp = k, int((neg > thr).sum())
    y = np.r_[np.ones(len(s_atk)), np.zeros(len(neg))]
    res["pr"] = {"precision": tp / (tp + fp) if tp + fp else float("nan"), "recall": k / n,
                 "pr_auc": float(average_precision_score(y, np.r_[s_atk, neg])),
                 "prevalence": len(s_atk) / len(y)}

    print(f"\n=== {name} ===")
    print(f"threshold ({FP_BUDGET_PCT}th pct of val normal): {thr:.4f}  (val FP {res['val_fp_rate']*100:.2f}%, tuning set)")
    for key, label in (("test_normal", "test normal (baseline)"), ("session_normal", "session normal (attack run)")):
        f = res[key]
        print(f"  FP {label:28s}: {f['fp_rate']*100:5.2f}%  [{f['fp_rate_ci95'][0]*100:.2f}, "
              f"{f['fp_rate_ci95'][1]*100:.2f}]  ({f['false_pos']}/{f['n']})  {f['fp_per_hour']:.1f}/hr")
    print(f"  {'attack type':14s} {'detected':>9s}  {'rate':>6s}  95% CI")
    for t, r in res["per_attack"].items():
        print(f"  {t:14s} {r['detected']:>4d}/{r['n']:<4d}  {r['rate']*100:5.1f}%  "
              f"[{r['ci95'][0]*100:.1f}, {r['ci95'][1]*100:.1f}]")
    o, p = res["overall_detection"], res["pr"]
    print(f"  {'overall':14s} {o['detected']:>4d}/{o['n']:<4d}  {o['rate']*100:5.1f}%  "
          f"[{o['ci95'][0]*100:.1f}, {o['ci95'][1]*100:.1f}]")
    print(f"  precision {p['precision']:.3f}  recall {p['recall']:.3f}  PR-AUC {p['pr_auc']:.3f}  "
          f"(prevalence {p['prevalence']*100:.1f}%)")
    return res, (s_test, s_sess, s_atk)

res_iso, sc_iso = evaluate("IsolationForest", iso_score)
res_ae,  sc_ae  = evaluate("Autoencoder",     recon_err)

# ---------- latency ----------
one = Xatk[:1]
t0 = time.perf_counter()
for _ in range(1000): iso.score_samples(one)
print(f"\n(latency below is on this training host, not the Pi)")
print(f"IsolationForest latency: {(time.perf_counter()-t0)/1000*1e6:.1f} us/window")

one_t = torch.tensor(one, dtype=torch.float32)
t0 = time.perf_counter()
with torch.no_grad():
    for _ in range(1000): ae(one_t)
print(f"Autoencoder latency:     {(time.perf_counter()-t0)/1000*1e6:.1f} us/window")

# ---------- export ----------
joblib.dump(iso, OUT / "model_isoforest.joblib")
joblib.dump(scaler, OUT / "scaler.joblib")
torch.onnx.export(ae, one_t, OUT / "model_autoencoder.onnx", dynamo=False,
                  input_names=["features"], output_names=["reconstruction"],
                  dynamic_axes={"features": {0: "batch"}, "reconstruction": {0: "batch"}})

meta = {
    "features": FEATURES,
    "iso_threshold": res_iso["threshold"],
    "ae_threshold": res_ae["threshold"],
    "scaler_mean": scaler.mean_.tolist(),
    "scaler_scale": scaler.scale_.tolist(),
    # keyed relative to the data dir so hashes compare across PC/Pi checkouts
    "inputs": {str(p.relative_to(DATA)) if p.is_relative_to(DATA) else p.name: sha256(p)
               for p in (BASELINE, ATTACKS, LABELS)},
    "split": {"method": "chronological", "fractions": SPLIT, "purge_s": PURGE_S,
              "train": [float(train_df.ts.min()), float(train_df.ts.max()), len(train_df)],
              "val":   [float(val_df.ts.min()),   float(val_df.ts.max()),   len(val_df)],
              "test":  [float(test_df.ts.min()),  float(test_df.ts.max()),  len(test_df)]},
    "attack_labeling": {"window_s": WINDOW_S, "guard_s": GUARD_S,
                        "network_devices": sorted(NET_DEVICES),
                        "excluded_labels": skipped.label.tolist()},
    "evaluation": {"isolation_forest": res_iso, "autoencoder": res_ae},
}
json.dump(meta, open(OUT / "model_meta.json", "w"), indent=2)
print("\nsaved: model_isoforest.joblib, model_autoencoder.onnx, scaler.joblib, model_meta.json")

# ---------- plot ----------
try:
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 2, figsize=(12,4))
    for a, (s_test, s_sess, s_atk), thr, name in [(ax[0], sc_iso, res_iso["threshold"], "IsolationForest"),
                                                   (ax[1], sc_ae,  res_ae["threshold"],  "Autoencoder")]:
        a.hist(s_test, bins=50, alpha=0.5, label="test normal", density=True)
        a.hist(s_sess, bins=50, alpha=0.5, label="session normal", density=True)
        a.hist(s_atk,  bins=50, alpha=0.5, label="attack", density=True)
        a.axvline(thr, color="k", ls="--", label="threshold (val)")
        a.set_title(name); a.set_xlabel("anomaly score"); a.legend(); a.set_yscale("log")
    plt.tight_layout(); plt.savefig(OUT / "score_distributions.png", dpi=120)
    print("saved: score_distributions.png")
except Exception as e:
    print("plot skipped:", e)
