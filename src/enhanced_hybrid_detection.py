import os
import pandas as pd
import joblib
from scipy import sparse

DATA_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\data"
MODEL_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\models"
REPORT_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# TUNABLE PARAMETERS
RF_THRESHOLD = 0.4  # Lower = more sensitive for known attacks
IF_THRESHOLD_PERCENTILE = 95  # Flag top 5% most anomalous events

input_file = os.path.join(DATA_DIR, "combined_train.csv")  # Change to any log
output_file = os.path.join(REPORT_DIR, "enhanced_hybrid_predictions.csv")

# Load log
print(f"✅ Reading log: {input_file}")
df = pd.read_csv(input_file)
print(f"✅ Loaded {len(df):,} rows.")

# Load models
rf_hasher = joblib.load(os.path.join(MODEL_DIR, "rf_hasher.joblib"))
rf_scaler = joblib.load(os.path.join(MODEL_DIR, "rf_scaler.joblib"))
rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_supervised_sparse.joblib"))

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

# Timestamp features
if "hour" in rf_num_cols or "hour" in if_num_cols:
    dt = pd.to_datetime(df.get("Date and Time", ""), errors="coerce")
    df["hour"] = dt.dt.hour.fillna(0).astype(int)
    df["dayofweek"] = dt.dt.dayofweek.fillna(0).astype(int)
    df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)

# Ensure numeric
for c in rf_num_cols + if_num_cols:
    df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

# RF PREDICTION with custom threshold
cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
X_cat_rf = rf_hasher.transform(cat_dicts)
X_num_rf = rf_scaler.transform(df[rf_num_cols])
X_rf = sparse.hstack([X_cat_rf, sparse.csr_matrix(X_num_rf)]).tocsr()
rf_probs = rf_model.predict_proba(X_rf)[:,1]
df["rf_malware_prob"] = rf_probs
df["rf_flag"] = (rf_probs >= RF_THRESHOLD).astype(int)

# IF PREDICTION with percentile threshold
X_cat_if = if_hasher.transform(cat_dicts)
X_num_if = if_scaler.transform(df[if_num_cols])
X_if = sparse.hstack([X_cat_if, sparse.csr_matrix(X_num_if)]).tocsr()
if_scores = -if_model.decision_function(X_if)
df["if_anomaly_score"] = if_scores

# Use percentile-based threshold for IF
if_threshold_value = df["if_anomaly_score"].quantile(IF_THRESHOLD_PERCENTILE / 100)
df["if_flag"] = (if_scores >= if_threshold_value).astype(int)

# FINAL COMBINED CLASSIFICATION
def classify_threat(row):
    if row["rf_flag"] == 1 and row["if_flag"] == 1:
        return "HIGH-CONFIDENCE RANSOMWARE"
    elif row["rf_flag"] == 1 and row["if_flag"] == 0:
        return "KNOWN RANSOMWARE PATTERN"
    elif row["rf_flag"] == 0 and row["if_flag"] == 1:
        return "NOVEL/UNKNOWN ANOMALY"
    else:
        return "BENIGN"

df["threat_classification"] = df.apply(classify_threat, axis=1)
df["malware_detected"] = ((df["rf_flag"] == 1) | (df["if_flag"] == 1)).astype(int)

# Save results
df.to_csv(output_file, index=False)
print(f"✅ Enhanced hybrid predictions saved to: {output_file}")

# Summary
print("\n" + "="*80)
print("ENHANCED HYBRID DETECTION SUMMARY")
print("="*80)
print(f"Total events analyzed: {len(df):,}")
print(f"\nDetection Results:")
print(f"  High-confidence ransomware (Both models): {(df['threat_classification']=='HIGH-CONFIDENCE RANSOMWARE').sum()}")
print(f"  Known ransomware pattern (RF only): {(df['threat_classification']=='KNOWN RANSOMWARE PATTERN').sum()}")
print(f"  Novel/unknown anomaly (IF only): {(df['threat_classification']=='NOVEL/UNKNOWN ANOMALY').sum()}")
print(f"  Benign (Neither): {(df['threat_classification']=='BENIGN').sum()}")
print(f"\nTotal malware detected: {df['malware_detected'].sum()}")

print("\nSample of detected threats:")
print(df[df["malware_detected"]==1][["Source", "Event ID", "rf_malware_prob", "if_anomaly_score", "threat_classification"]].head(10))
