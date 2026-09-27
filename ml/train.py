#!/usr/bin/env python3
"""Stage 5: train IsolationForest + PyTorch autoencoder on normal IoT traffic,
evaluate both against labeled attacks."""

import numpy as np, pandas as pd, joblib, time, json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import torch, torch.nn as nn

BASELINE = "baseline_normal.csv"
ATTACKS  = "attacks.csv"
LABELS   = "labels.csv"
DROP = ["ts", "mac", "device_class"]
SEED = 42
np.random.seed(SEED); torch.manual_seed(SEED)

# ---------- load ----------
base = pd.read_csv(BASELINE)
atk  = pd.read_csv(ATTACKS)
lab  = pd.read_csv(LABELS)

FEATURES = [c for c in base.columns if c not in DROP]

# label attack rows by timestamp membership
def label_row(ts):
    for _, r in lab.iterrows():
        if r.start <= ts <= r.end:
            return r.label
    return "normal"

atk["attack_type"] = atk["ts"].apply(label_row)
atk_only = atk[atk.attack_type != "normal"].copy()
print(f"baseline rows: {len(base)}")
print(f"attack rows (labeled): {len(atk_only)}  types: {atk_only.attack_type.value_counts().to_dict()}")

# ---------- split normal: train vs held-out FP test ----------
X = base[FEATURES].values
X_train, X_fp = train_test_split(X, test_size=0.2, random_state=SEED)
X_atk = atk_only[FEATURES].values

scaler = StandardScaler().fit(X_train)
Xtr, Xfp, Xatk = scaler.transform(X_train), scaler.transform(X_fp), scaler.transform(X_atk)

# ---------- Isolation Forest ----------
iso = IsolationForest(n_estimators=200, contamination=0.01, random_state=SEED)
iso.fit(Xtr)
# higher = more anomalous
iso_fp  = -iso.score_samples(Xfp)
iso_atk = -iso.score_samples(Xatk)

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

ae_fp  = recon_err(Xfp)
ae_atk = recon_err(Xatk)

# ---------- thresholds: 99th percentile of NORMAL held-out ----------
def evaluate(name, fp_scores, atk_scores, atk_df):
    thr = np.percentile(fp_scores, 99)  # ~1% false positive budget
    detected = atk_scores > thr
    fp_rate = (fp_scores > thr).mean()
    # false alarms per hour: normal windows are 10s -> 360/hr
    fa_per_hr = fp_rate * 360
    print(f"\n=== {name} ===")
    print(f"threshold (99th pct normal): {thr:.4f}")
    print(f"overall detection: {detected.mean()*100:.1f}%  ({detected.sum()}/{len(detected)})")
    print(f"false-positive rate on normal: {fp_rate*100:.2f}%  (~{fa_per_hr:.1f} false alarms/hour)")
    print("per-attack detection:")
    tmp = atk_df.copy(); tmp["detected"] = detected
    for t, g in tmp.groupby("attack_type"):
        print(f"    {t:12s}: {g.detected.mean()*100:5.1f}%  ({g.detected.sum()}/{len(g)})")
    return thr

thr_iso = evaluate("IsolationForest", iso_fp, iso_atk, atk_only)
thr_ae  = evaluate("Autoencoder",     ae_fp,  ae_atk, atk_only)

# ---------- latency ----------
one = Xatk[:1]
t0 = time.perf_counter()
for _ in range(1000): iso.score_samples(one)
print(f"\nIsolationForest latency: {(time.perf_counter()-t0)/1000*1e6:.1f} us/window")

one_t = torch.tensor(one, dtype=torch.float32)
t0 = time.perf_counter()
with torch.no_grad():
    for _ in range(1000): ae(one_t)
print(f"Autoencoder latency:     {(time.perf_counter()-t0)/1000*1e6:.1f} us/window")

# ---------- export ----------
joblib.dump(iso, "model_isoforest.joblib")
joblib.dump(scaler, "scaler.joblib")
torch.onnx.export(ae, one_t, "model_autoencoder.onnx",
                  input_names=["features"], output_names=["reconstruction"],
                  dynamic_axes={"features": {0: "batch"}, "reconstruction": {0: "batch"}})

meta = {
    "features": FEATURES,
    "iso_threshold": float(thr_iso),
    "ae_threshold": float(thr_ae),
    "scaler_mean": scaler.mean_.tolist(),
    "scaler_scale": scaler.scale_.tolist(),
}
json.dump(meta, open("model_meta.json", "w"), indent=2)
print("\nsaved: model_isoforest.joblib, model_autoencoder.onnx, scaler.joblib, model_meta.json")

# ---------- plot ----------
try:
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 2, figsize=(12,4))
    for a, fp, at, thr, name in [(ax[0], iso_fp, iso_atk, thr_iso, "IsolationForest"),
                                  (ax[1], ae_fp, ae_atk, thr_ae, "Autoencoder")]:
        a.hist(fp, bins=50, alpha=0.6, label="normal", density=True)
        a.hist(at, bins=50, alpha=0.6, label="attack", density=True)
        a.axvline(thr, color="k", ls="--", label="threshold")
        a.set_title(name); a.set_xlabel("anomaly score"); a.legend(); a.set_yscale("log")
    plt.tight_layout(); plt.savefig("score_distributions.png", dpi=120)
    print("saved: score_distributions.png")
except Exception as e:
    print("plot skipped:", e)