import os
import pandas as pd
import joblib
from scipy import sparse

DATA_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\data"
MODEL_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\models"
REPORT_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\reports"
os.makedirs(REPORT_DIR, exist_ok=True)

input_file = os.path.join(DATA_DIR, "combined_train.csv")  # Change to any log
output_file = os.path.join(REPORT_DIR, "hybrid_predictions.csv")

# Load log
print(f"✅ Reading log: {input_file}")
df = pd.read_csv(input_file)
print(f"✅ Loaded {len(df):,} rows.")

# Load RF models
rf_hasher = joblib.load(os.path.join(MODEL_DIR, "rf_hasher.joblib"))
rf_scaler = joblib.load(os.path.join(MODEL_DIR, "rf_scaler.joblib"))
rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_supervised_sparse.joblib"))

# Load IF models
if_hasher = joblib.load(os.path.join(MODEL_DIR, "if_hasher.joblib"))
if_scaler = joblib.load(os.path.join(MODEL_DIR, "if_scaler.joblib"))
if_model = joblib.load(os.path.join(MODEL_DIR, "isolation_forest_retrained.joblib"))

# Feature setup
cat_cols = ["Level", "Source", "Task Category"]
rf_num_cols = list(rf_scaler.feature_names_in_)
if_num_cols = list(if_scaler.feature_names_in_)

# Add missing columns
for c in cat_cols + rf_num_cols + if_num_cols:
    if c not in df.columns:
        df[c] = 0 if c in rf_num_cols or c in if_num_cols else "NA"

# Timestamp features if needed
if "hour" in rf_num_cols or "hour" in if_num_cols:
    dt = pd.to_datetime(df.get("Date and Time", ""), errors="coerce")
    df["hour"] = dt.dt.hour.fillna(0).astype(int)
    df["dayofweek"] = dt.dt.dayofweek.fillna(0).astype(int)
    df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)

# Ensure numeric
for c in rf_num_cols + if_num_cols:
    df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

# RF PREDICTION
cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
X_cat_rf = rf_hasher.transform(cat_dicts)
X_num_rf = rf_scaler.transform(df[rf_num_cols])
X_rf = sparse.hstack([X_cat_rf, sparse.csr_matrix(X_num_rf)]).tocsr()
rf_preds = rf_model.predict(X_rf)
rf_probs = rf_model.predict_proba(X_rf)[:,1]

# IF PREDICTION
X_cat_if = if_hasher.transform(cat_dicts)
X_num_if = if_scaler.transform(df[if_num_cols])
X_if = sparse.hstack([X_cat_if, sparse.csr_matrix(X_num_if)]).tocsr()
if_preds = if_model.predict(X_if)  # -1 = anomaly, 1 = normal
if_scores = -if_model.decision_function(X_if)  # Higher = more anomalous

# Convert IF predictions: -1 (anomaly) -> 1 (malware), 1 (normal) -> 0
df["if_pred"] = (if_preds == -1).astype(int)
df["if_anomaly_score"] = if_scores
df["rf_pred"] = rf_preds
df["rf_malware_prob"] = rf_probs

# COMBINED FLAG: both models agree
df["combined_flag"] = ((df["rf_pred"] == 1) & (df["if_pred"] == 1)).astype(int)

df.to_csv(output_file, index=False)
print(f"✅ Hybrid predictions saved to: {output_file}")
print("\nSample flagged by BOTH models:")
print(df[df["combined_flag"]==1].head(10))
print(f"\nTotal flagged by RF: {df['rf_pred'].sum()}")
print(f"Total flagged by IF: {df['if_pred'].sum()}")
print(f"Total flagged by BOTH: {df['combined_flag'].sum()}")
