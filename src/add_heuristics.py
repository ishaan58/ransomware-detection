"""
add_heuristics.py — adds rule-based context features.
Saves: heuristic_predictions.csv
"""
import os, joblib, json
import pandas as pd, numpy as np
from scipy import sparse

DATA_DIR = r"C:\islabproject\data"
MODEL_DIR = r"C:\islabproject\models"
REPORT_DIR = r"C:\islabproject\reports"
os.makedirs(REPORT_DIR, exist_ok=True)

df = pd.read_csv(os.path.join(DATA_DIR, "test_enriched.csv"))
print(f"✅ Loaded {len(df):,} test rows.")

hasher = joblib.load(os.path.join(MODEL_DIR, "hasher.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.joblib"))

cat_cols = ["Level", "Source", "Task Category"]
num_cols = ["Event ID"]
for c in cat_cols: 
    if c not in df.columns: df[c] = "NA"
for c in num_cols:
    if c not in df.columns: df[c] = 0

df["hour"] = pd.to_datetime(df["Date and Time"], errors="coerce").dt.hour.fillna(0)
df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)
df["keyword_hit"] = df["Source"].astype(str).str.contains("vssadmin|cipher|ransom|encrypt", case=False).astype(int)

X_cat = hasher.transform(df[cat_cols].astype(str).to_dict(orient="records"))
# ✅ Include dayofweek to match training scaler input
df["dayofweek"] = pd.to_datetime(df["Date and Time"], errors="coerce").dt.dayofweek.fillna(0)
X_num = scaler.transform(df[num_cols + ["hour", "dayofweek", "is_offhours"]])
X = sparse.hstack([X_cat, sparse.csr_matrix(X_num)]).tocsr()

scores = -model.decision_function(X)
thr_info = json.load(open(os.path.join(MODEL_DIR, "best_threshold.json")))
thr_val = thr_info["thr_val"]
df["if_pred"] = (scores >= thr_val).astype(int)
df["anomaly_score"] = scores

df["combined_flag"] = ((df["if_pred"] == 1) & ((df["is_offhours"] == 1) | (df["keyword_hit"] == 1))).astype(int)
df.to_csv(os.path.join(REPORT_DIR, "heuristic_predictions.csv"), index=False)
print("✅ Heuristic-enhanced predictions saved.")
