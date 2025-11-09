from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib, os, pandas as pd, numpy as np
from sklearn.feature_extraction import FeatureHasher
from scipy import sparse
import traceback

app = Flask(__name__)
CORS(app)

# ===============================
# MODEL LOADING
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

# RF Models
RF_MODEL_PATH = os.path.join(MODEL_DIR, "rf_supervised_sparse.joblib")
RF_HASHER_PATH = os.path.join(MODEL_DIR, "rf_hasher.joblib")
RF_SCALER_PATH = os.path.join(MODEL_DIR, "rf_scaler.joblib")

# IF Models
IF_MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_retrained.joblib")
IF_HASHER_PATH = os.path.join(MODEL_DIR, "if_hasher.joblib")
IF_SCALER_PATH = os.path.join(MODEL_DIR, "if_scaler.joblib")

rf_model = None
rf_hasher = None
rf_scaler = None
if_model = None
if_hasher = None
if_scaler = None

try:
    rf_model = joblib.load(RF_MODEL_PATH)
    rf_hasher = joblib.load(RF_HASHER_PATH)
    rf_scaler = joblib.load(RF_SCALER_PATH)
    print(f"✅ RF models loaded from {MODEL_DIR}")
except Exception as e:
    print(f"❌ Failed to load RF models: {e}")

try:
    if_model = joblib.load(IF_MODEL_PATH)
    if_hasher = joblib.load(IF_HASHER_PATH)
    if_scaler = joblib.load(IF_SCALER_PATH)
    print(f"✅ IF models loaded from {MODEL_DIR}")
except Exception as e:
    print(f"❌ Failed to load IF models: {e}")

# Tunable parameters
RF_THRESHOLD = 0.4  # Lower threshold for known ransomware
IF_THRESHOLD_PERCENTILE = 95  # Top 5% anomalies

# ===============================
# PREPROCESSING PIPELINE
# ===============================
def preprocess_logs(df: pd.DataFrame):
    """Clean and prepare log data for both RF and IF"""
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
    """Extract RF features"""
    cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
    X_cat = rf_hasher.transform(cat_dicts)
    
    expected_num_cols = list(rf_scaler.feature_names_in_)
    df_num = df[[c for c in expected_num_cols if c in df.columns]]
    X_num = rf_scaler.transform(df_num)
    
    X = sparse.hstack([X_cat, sparse.csr_matrix(X_num.astype(np.float32))]).tocsr()
    return X

def get_if_features(df, cat_cols, num_cols):
    """Extract IF features"""
    cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
    X_cat = if_hasher.transform(cat_dicts)
    
    expected_num_cols = list(if_scaler.feature_names_in_)
    df_num = df[[c for c in expected_num_cols if c in df.columns]]
    X_num = if_scaler.transform(df_num)
    
    X = sparse.hstack([X_cat, sparse.csr_matrix(X_num.astype(np.float32))]).tocsr()
    return X

# ===============================
# ROUTE: FILE UPLOAD + PREDICTION
# ===============================
@app.route("/api/upload", methods=["POST"])
def upload_csv():
    if rf_model is None or if_model is None:
        return jsonify({"error": "Models not loaded on server"}), 500
    
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    f = request.files["file"]
    
    try:
        df = pd.read_csv(f)
    except Exception as e:
        return jsonify({"error": f"Invalid or unreadable CSV: {str(e)}"}), 400
    
    try:
        df = preprocess_logs(df)
        
        cat_cols = ["Level", "Source", "Task Category"]
        num_cols = ["Event ID"]
        
        # RF PREDICTION with threshold 0.4
        X_rf = get_rf_features(df, cat_cols, num_cols)
        rf_probs = rf_model.predict_proba(X_rf)[:, 1]
        df["rf_malware_prob"] = rf_probs
        df["rf_flag"] = (rf_probs >= RF_THRESHOLD).astype(int)
        
        # IF PREDICTION with percentile threshold
        X_if = get_if_features(df, cat_cols, num_cols)
        if_scores = -if_model.decision_function(X_if)
        df["if_anomaly_score"] = if_scores
        
        if_threshold_value = df["if_anomaly_score"].quantile(IF_THRESHOLD_PERCENTILE / 100)
        df["if_flag"] = (if_scores >= if_threshold_value).astype(int)
        
        # THREAT CLASSIFICATION
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
        
        # SUMMARY STATISTICS
        total_records = len(df)
        malware_detected = df["malware_detected"].sum()
        high_confidence = (df["threat_classification"] == "HIGH-CONFIDENCE RANSOMWARE").sum()
        known_pattern = (df["threat_classification"] == "KNOWN RANSOMWARE PATTERN").sum()
        novel_anomaly = (df["threat_classification"] == "NOVEL/UNKNOWN ANOMALY").sum()
        benign = (df["threat_classification"] == "BENIGN").sum()
        
        malware_percentage = round(100 * malware_detected / total_records, 2) if total_records > 0 else 0
        
        summary = {
            "total_records": int(total_records),
            "malware_detected": int(malware_detected),
            "malware_percentage": malware_percentage,
            "threat_breakdown": {
                "high_confidence_ransomware": int(high_confidence),
                "known_ransomware_pattern": int(known_pattern),
                "novel_unknown_anomaly": int(novel_anomaly),
                "benign": int(benign),
            }
        }
        
        # Flagged samples
        flagged = df[df["malware_detected"] == 1][
            ["Source", "Event ID", "Level", "threat_classification", "rf_malware_prob", "if_anomaly_score"]
        ].head(10)
        flagged_list = flagged.to_dict(orient="records")
        
        return jsonify({"summary": summary, "flagged": flagged_list})
    
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ===============================
# ROUTE: HEALTH CHECK
# ===============================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "Ransomware Detection API running ✅",
        "models_loaded": {
            "rf": bool(rf_model),
            "if": bool(if_model)
        }
    })

# ===============================
# ENTRY POINT
# ===============================
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
