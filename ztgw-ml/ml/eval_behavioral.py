"""Behavioral-layer detection eval for the STM32 (serial-bridged, invisible to the
network detector). Catches value_drift + beacon at the MQTT-behavior layer.
Same rigor as the network eval: one-class train on normal, chronological split,
threshold on val, FP on held-out test, per-attack detection with 95% CIs."""
import csv, math
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

DEVICE="stm32-01"
FEATURES=["msg_count","bytes_total","msg_size_mean","msg_size_std","msg_size_max",
          "iat_mean","iat_std","rate_per_sec","unique_topics","val_mean","val_std"]
def fnum(v):
    try: return float(v)
    except: return 0.0
def load(f): return [r for r in csv.DictReader(open(f)) if r["device"]==DEVICE]
def wilson(k,n):
    if n==0: return (0,0)
    z=1.96; p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return (max(0,c-h)*100, min(1,c+h)*100)

labels=[]
for r in csv.DictReader(open("labels.csv")):
    if r["device"]==DEVICE: labels.append((r["label"],float(r["start"]),float(r["end"])))
print("STM32 attacks in labels:", [l[0] for l in labels])
def atk_of(ts):
    for name,s,e in labels:
        if s<=ts<=e: return name
    return None

base=sorted(load("baseline_mqtt.csv"), key=lambda r:fnum(r["ts"]))
Xb=np.array([[fnum(r[c]) for c in FEATURES] for r in base])
n=len(Xb); i1=int(n*.7); i2=int(n*.85)
Xtr,Xval,Xte=Xb[:i1],Xb[i1:i2],Xb[i2:]
print(f"normal baseline: train {len(Xtr)} val {len(Xval)} test {len(Xte)} (chronological)")
sc=StandardScaler().fit(Xtr)
iso=IsolationForest(n_estimators=200,contamination=0.01,random_state=42).fit(sc.transform(Xtr))
thr=np.percentile(-iso.score_samples(sc.transform(Xval)),99)

sess=sorted(load("mqtt_behavior.csv"), key=lambda r:fnum(r["ts"]))
atk=[(r,atk_of(fnum(r["ts"]))) for r in sess if atk_of(fnum(r["ts"]))]
sn =[r for r in sess if not atk_of(fnum(r["ts"]))]
def S(rows,get=lambda x:x):
    X=np.array([[fnum(get(r)[c]) for c in FEATURES] for r in rows])
    return -iso.score_samples(sc.transform(X)) if len(X) else np.array([])
sc_te=-iso.score_samples(sc.transform(Xte))
sc_sn=S(sn)
sc_atk=S(atk, lambda t:t[0])

print(f"\n=== Behavioral IsolationForest (STM32) ===")
print(f"threshold (99th pct val normal): {thr:.4f}")
for nm,s,N in [("FP test normal (baseline)",sc_te,len(sc_te)),
               ("FP session normal (attack run)",sc_sn,len(sc_sn))]:
    k=(s>thr).sum(); lo,hi=wilson(k,N)
    print(f"  {nm:32s}: {100*k/N:5.2f}%  [{lo:.1f},{hi:.1f}]  ({k}/{N})")

from collections import defaultdict
by=defaultdict(lambda:[0,0])
for (r,a),v in zip(atk,sc_atk):
    by[a][1]+=1
    if v>thr: by[a][0]+=1
print(f"  {'attack type':18s} detected   rate    95% CI")
td=tt=0
for a,(d,t) in sorted(by.items()):
    lo,hi=wilson(d,t); td+=d; tt+=t
    print(f"  {a:18s} {d:3d}/{t:<3d}  {100*d/t:5.1f}%  [{lo:.1f},{hi:.1f}]")
lo,hi=wilson(td,tt)
print(f"  {'overall':18s} {td:3d}/{tt:<3d}  {100*td/tt:5.1f}%  [{lo:.1f},{hi:.1f}]")
fp=(sc_sn>thr).sum()+(sc_te>thr).sum()
print(f"  precision {td/(td+fp) if td+fp else 0:.3f}  recall {td/tt:.3f}  (prevalence {100*tt/(tt+len(sc_sn)):.1f}%)")
