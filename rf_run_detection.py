import os
import pandas as pd
import joblib
from scipy import sparse

DATA_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\data"
MODEL_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\models"
REPORT_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\reports"
os.makedirs(REPORT_DIR, exist_ok=True)

input_file = os.path.join(DATA_DIR, "x.csv")  # or your test log
output_file = os.path.join(REPORT_DIR, "benign_ishaan_predictions.csv")

# 1. Load log
print(f"\u2705 Reading log: {input_file}")
df = pd.read_csv(input_file)
print(f"\u2705 Loaded {len(df):,} rows.")

# 2. Guarantee columns match those used in model training
# Load scaler/hasher/model
hasher = joblib.load(os.path.join(MODEL_DIR, "rf_hasher.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "rf_scaler.joblib"))
model = joblib.load(os.path.join(MODEL_DIR, "rf_supervised_sparse.joblib"))

# Pull the actual numeric columns scaler expects
required_num_cols = list(scaler.feature_names_in_)
# Pull the actual categorical columns from the hasher training (they are in model meta or just use your training script order):
cat_cols = ["Level", "Source", "Task Category"]  # Your project always uses these

# Add missing columns if needed, fill with safe values
for c in cat_cols:
    if c not in df.columns:
        df[c] = "NA"
for c in required_num_cols:
    if c not in df.columns:
        df[c] = 0

# Ensure all numerics really are numbers
for c in required_num_cols:
    df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

# Feature engineer timestamp columns if needed
if "hour" in required_num_cols or "dayofweek" in required_num_cols or "is_offhours" in required_num_cols:
    try:
        dt = pd.to_datetime(df["Date and Time"], errors="coerce")
    except:
        dt = pd.Series([0]*len(df))
    if "hour" in required_num_cols:
        df["hour"] = dt.dt.hour.fillna(0).astype(int)
    if "dayofweek" in required_num_cols:
        df["dayofweek"] = dt.dt.dayofweek.fillna(0).astype(int)
    if "is_offhours" in required_num_cols:
        df["is_offhours"] = ((df.get("hour",0) < 6) | (df.get("hour",0) > 22)).astype(int)

# Categorical features
cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
X_cat = hasher.transform(cat_dicts)

# Numeric features: in the EXACT order/model expects
X_num = scaler.transform(df[required_num_cols])

X = sparse.hstack([X_cat, sparse.csr_matrix(X_num)]).tocsr()

# Predict using your RF model
preds = model.predict(X)
probs = model.predict_proba(X)[:,1]
df["rf_pred"] = preds
df["malware_prob"] = probs

df.to_csv(output_file, index=False)
print(f"\u2705 RF predictions saved to: {output_file}")
print("\nSample flagged rows:")
print(df[df["rf_pred"]==1].head(10))
