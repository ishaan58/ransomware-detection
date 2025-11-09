"""
tune_thresholds.py — tune percentile thresholds for IsolationForest.
"""
import os, json, joblib
import pandas as pd, numpy as np
from scipy import sparse
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score
import matplotlib.pyplot as plt, seaborn as sns

DATA_DIR = r"C:\islabproject\data"
MODEL_DIR = r"C:\islabproject\models"
REPORT_DIR = r"C:\islabproject\reports"
os.makedirs(REPORT_DIR, exist_ok=True)

test_files = [os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR) if "test" in f.lower()]
test_dfs = [pd.read_csv(f) for f in test_files]
df = pd.concat(test_dfs, ignore_index=True)
print(f"🧪 Loaded {len(df):,} test rows from {len(test_files)} files.")

df["Event ID"] = pd.to_numeric(df["Event ID"], errors="coerce").fillna(0)
df["Date and Time"] = pd.to_datetime(df["Date and Time"], errors="coerce")
df["hour"] = df["Date and Time"].dt.hour.fillna(0).astype(int)
df["dayofweek"] = df["Date and Time"].dt.dayofweek.fillna(0).astype(int)
df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)

cat_cols = ["Level", "Source", "Task Category"]
num_cols = ["Event ID", "hour", "dayofweek", "is_offhours"]
for c in cat_cols:
    if c not in df.columns: df[c] = "NA"
for c in num_cols:
    if c not in df.columns: df[c] = 0

y_true = df.get("Label", pd.Series([0]*len(df))).astype(int).values

hasher = joblib.load(os.path.join(MODEL_DIR, "hasher.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.joblib"))

def transform_sparse(df):
    cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
    X_cat = hasher.transform(cat_dicts)
    X_num = scaler.transform(df[num_cols])
    return sparse.hstack([X_cat, sparse.csr_matrix(X_num)]).tocsr()

X_test = transform_sparse(df)
scores = -model.decision_function(X_test)

thresholds = [95, 97, 98, 99, 99.5, 99.9]
rows = []
for thr in thresholds:
    val = np.percentile(scores, thr)
    preds = (scores >= val).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y_true, preds, average="binary", zero_division=0)
    auc = roc_auc_score(y_true, scores)
    ap = average_precision_score(y_true, scores)
    rows.append({"thr_pct": thr, "thr_val": val, "precision": p, "recall": r, "f1": f, "AUC": auc, "AP": ap})
    print(f"{thr}% → P={p:.4f} R={r:.4f} F1={f:.4f}")

df_res = pd.DataFrame(rows)
df_res.to_csv(os.path.join(REPORT_DIR, "threshold_tuning.csv"), index=False)
best = df_res.iloc[df_res["f1"].idxmax()].to_dict()
json.dump(best, open(os.path.join(MODEL_DIR, "best_threshold.json"), "w"), indent=2)
print("✅ Saved best threshold:", best)

sns.lineplot(data=df_res, x="thr_pct", y="precision", marker="o", label="precision")
sns.lineplot(data=df_res, x="thr_pct", y="recall", marker="o", label="recall")
sns.lineplot(data=df_res, x="thr_pct", y="f1", marker="o", label="f1")
plt.title("Threshold tuning (IF)")
plt.grid(True)
plt.savefig(os.path.join(REPORT_DIR, "threshold_tuning.png"), bbox_inches="tight")
plt.close()
