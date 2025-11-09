import os
import pandas as pd
import joblib
from scipy import sparse
import json

DATA_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\data"
MODEL_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\models"
REPORT_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\reports"
os.makedirs(REPORT_DIR, exist_ok=True)

wannacry_path = os.path.join(DATA_DIR, "wannacry.csv")
df = pd.read_csv(wannacry_path)
print(f"\u2705 Loaded {len(df):,} rows from wannacry.csv.")

# Ensure all required columns exist
cat_cols = ["Level", "Source", "Task Category"]
num_cols = ["Event ID"]
for c in cat_cols:
    if c not in df.columns:
        df[c] = "NA"
for c in num_cols:
    if c not in df.columns:
        df[c] = 0

# Clean numeric columns: removes any symbols, ensures integer type
def fix_int_column(col):
    return pd.to_numeric(col.astype(str).str.replace(r"[^\d.]", "", regex=True), errors="coerce").fillna(0).astype(int)
df["Event ID"] = fix_int_column(df["Event ID"])

# Extract timestamp features safely
try:
    df["hour"] = pd.to_datetime(df["Date and Time"], format="%Y-%m-%d %H:%M:%S", errors="coerce").dt.hour.fillna(0).astype(int)
    df["dayofweek"] = pd.to_datetime(df["Date and Time"], format="%Y-%m-%d %H:%M:%S", errors="coerce").dt.dayofweek.fillna(0).astype(int)
except:
    df["hour"] = pd.to_datetime(df["Date and Time"], errors="coerce").dt.hour.fillna(0).astype(int)
    df["dayofweek"] = pd.to_datetime(df["Date and Time"], errors="coerce").dt.dayofweek.fillna(0).astype(int)
df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)
df["keyword_hit"] = df["Source"].astype(str).str.contains(r"vssadmin|cipher|ransom|encrypt", case=False).astype(int)
# Ensure as int and no NaN
df["hour"] = pd.to_numeric(df["hour"], errors="coerce").fillna(0).astype(int)
df["dayofweek"] = pd.to_numeric(df["dayofweek"], errors="coerce").fillna(0).astype(int)
df["is_offhours"] = pd.to_numeric(df["is_offhours"], errors="coerce").fillna(0).astype(int)

# Load all transformers and models
hasher = joblib.load(os.path.join(MODEL_DIR, "hasher.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.joblib"))
try:
    thr_info = json.load(open(os.path.join(MODEL_DIR, "best_threshold.json")))
    thr_val = thr_info["thr_val"]
except Exception:
    thr_val = 0

# Encode and scale features (exact order!)
X_cat = hasher.transform(df[cat_cols].astype(str).to_dict(orient="records"))
X_num = scaler.transform(df[num_cols + ["hour", "dayofweek", "is_offhours"]])
X = sparse.hstack([X_cat, sparse.csr_matrix(X_num)]).tocsr()

# Inference and flagging
scores = -model.decision_function(X)
if hasattr(model, 'offset_'):
    threshold = getattr(model, 'offset_')
else:
    threshold = thr_val

# Make predictions
df["if_pred"] = (scores >= threshold).astype(int)
df["anomaly_score"] = scores
df["combined_flag"] = ((df["if_pred"] == 1) & ((df["is_offhours"] == 1) | (df["keyword_hit"] == 1))).astype(int)

# Save and print summary
result_path = os.path.join(REPORT_DIR, "wannacry_predictions.csv")
df.to_csv(result_path, index=False)
print(f"\u2705 Saved predicted results to {result_path}")
print(f"\n\u26a0\ufe0f Summary:")
print(df[["anomaly_score", "if_pred", "combined_flag"]].value_counts())
print("\nTop flagged events:")
print(df.loc[df["combined_flag"] == 1].head(10))
