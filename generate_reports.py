import os
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import joblib
from scipy import sparse

# ===============================
# MODEL LOADING
# ===============================
rf_model = joblib.load('models/rf_supervised_sparse.joblib')
rf_hasher = joblib.load('models/rf_hasher.joblib')
rf_scaler = joblib.load('models/rf_scaler.joblib')
if_model = joblib.load('models/isolation_forest_retrained.joblib')
if_hasher = joblib.load('models/if_hasher.joblib')
if_scaler = joblib.load('models/if_scaler.joblib')

# ===============================
# PREPROCESSING PIPELINE
# ===============================
def preprocess_logs(df: pd.DataFrame):
    for col in ["Level", "Source", "Task Category", "Event ID", "Date and Time"]:
        if col not in df.columns:
            df[col] = "NA"
    df["Event ID"] = pd.to_numeric(df["Event ID"], errors="coerce").fillna(0)
    df["Date and Time"] = pd.to_datetime(df["Date and Time"], errors="coerce")
    df["hour"] = df["Date and Time"].dt.hour.fillna(0).astype(int)
    df["dayofweek"] = df["Date and Time"].dt.dayofweek.fillna(0).astype(int)
    df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)
    return df

def get_rf_features(df, cat_cols, num_cols):
    cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
    X_cat = rf_hasher.transform(cat_dicts)
    expected_num_cols = list(rf_scaler.feature_names_in_)
    df_num = df[[c for c in expected_num_cols if c in df.columns]]
    # NEW: force numeric conversion, turn any non-numeric into 0!
    df_num = df_num.apply(pd.to_numeric, errors='coerce').fillna(0)
    X_num = rf_scaler.transform(df_num)
    X = sparse.hstack([X_cat, sparse.csr_matrix(X_num.astype(np.float32))]).tocsr()
    return X

def get_if_features(df, cat_cols, num_cols):
    cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
    X_cat = if_hasher.transform(cat_dicts)
    expected_num_cols = list(if_scaler.feature_names_in_)
    df_num = df[[c for c in expected_num_cols if c in df.columns]]
    df_num = df_num.apply(pd.to_numeric, errors='coerce').fillna(0)
    X_num = if_scaler.transform(df_num)
    X = sparse.hstack([X_cat, sparse.csr_matrix(X_num.astype(np.float32))]).tocsr()
    return X

RF_THRESHOLD = 0.4
IF_THRESHOLD_PERCENTILE = 95
cat_cols = ["Level", "Source", "Task Category"]
num_cols = ["Event ID"]
data_folder = 'data/'
report_folder = 'reports/'
# List your showcase/test files here:
files_for_demo = [
    'wannacry.csv',
    'keshav_logs.csv',
    'tanay_logs.csv',
    'x.csv',
    'test_fake_labeled.csv' 
]

os.makedirs(report_folder, exist_ok=True)

for fname in files_for_demo:
    fpath = os.path.join(data_folder, fname)
    if not os.path.exists(fpath):
        print(f'Skipping {fname} (file not found)')
        continue
    print(f'Processing: {fname}')
    df = pd.read_csv(fpath)
    df = preprocess_logs(df)
    # Ensure ALL expected numeric columns are numeric after preprocessing!
    expected_num_cols = list(rf_scaler.feature_names_in_)
    df[expected_num_cols] = df[expected_num_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
    # RF Prediction
    X_rf = get_rf_features(df, cat_cols, num_cols)
    rf_probs = rf_model.predict_proba(X_rf)[:, 1]
    df["rf_malware_prob"] = rf_probs
    df["rf_flag"] = (rf_probs >= RF_THRESHOLD).astype(int)
    # IF Prediction
    X_if = get_if_features(df, cat_cols, num_cols)
    if_scores = -if_model.decision_function(X_if)
    df["if_anomaly_score"] = if_scores
    if_threshold_value = np.percentile(df["if_anomaly_score"], IF_THRESHOLD_PERCENTILE)
    df["if_flag"] = (if_scores >= if_threshold_value).astype(int)
    # Hybrid classification
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
    # Save summary
    total = len(df)
    malware = df["malware_detected"].sum()
    malware_pct = round(100 * malware / total, 2) if total > 0 else 0
    breakdown = df["threat_classification"].value_counts().to_dict()
    summary_row = {
        'file': fname,
        'total_events': total,
        'malware_detected': int(malware),
        'malware_percentage': malware_pct,
        **breakdown
    }
    summf = os.path.join(report_folder, 'prediction_summary.csv')
    mode = 'a' if os.path.exists(summf) else 'w'
    pd.DataFrame([summary_row]).to_csv(summf, mode=mode, header=not os.path.exists(summf), index=False)
    print('Summary saved for', fname)
    # Confusion matrix if ground-truth exists
    if 'label' in df.columns:
        y_true = df['label']
        y_pred = df['malware_detected']
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Malware"])
        disp.plot(cmap=plt.cm.Blues, colorbar=False)
        plt.title(f"Confusion Matrix — {fname}")
        plt.savefig(os.path.join(report_folder, f"confusion_matrix_{fname.replace('.csv','')}.png"), dpi=120)
        plt.close()
        print('Confusion matrix plot saved for', fname)
    else:
        print("No 'label' column found; skipping confusion matrix.")
    print()
print('✓ All done! Check reports folder.')
