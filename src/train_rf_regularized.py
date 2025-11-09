import os, joblib, json
import pandas as pd, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import FeatureHasher
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score
from scipy import sparse

# --- CONFIG ---
DATA_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\data"
MODEL_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\models"
REPORT_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\reports"
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# --- LOAD DATA ---
df = pd.read_csv(os.path.join(DATA_DIR, "combined_train.csv"))
print(f"✅ Loaded {len(df):,} rows from combined_train.csv.")

y = df["Label"].astype(int)
X = df.drop(columns=["Label"])

# --- CATEGORICAL / NUMERIC SPLIT ---
cat_cols = [c for c in X.columns if X[c].dtype == object]
num_cols = [c for c in X.columns if c not in cat_cols]

for c in num_cols:
    X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0)

print(f"Detected {len(cat_cols)} categorical and {len(num_cols)} numeric columns.")

# --- FEATURE HASHING ---
hasher = FeatureHasher(n_features=512, input_type="dict")
cat_dicts = X[cat_cols].astype(str).to_dict(orient="records")
X_cat = hasher.transform(cat_dicts)

scaler = StandardScaler()
X_num = scaler.fit_transform(X[num_cols])

X_final = sparse.hstack([X_cat, sparse.csr_matrix(X_num)]).tocsr()
print(f"✅ Final feature matrix: {X_final.shape[0]} rows, {X_final.shape[1]} features (sparse)")

# --- TRAIN/VAL SPLIT ---
X_train, X_val, y_train, y_val = train_test_split(X_final, y, test_size=0.2, stratify=y, random_state=42)
print(f"Train: {X_train.shape}, Val: {X_val.shape}")

# --- TRAIN MODEL ---
rf = RandomForestClassifier(
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
    max_depth=30,
    n_estimators=400,
    min_samples_split=5,
    min_samples_leaf=2
)

rf.fit(X_train, y_train)
y_pred = rf.predict(X_val)

print("\n", classification_report(y_val, y_pred))
print("AUC:", roc_auc_score(y_val, rf.predict_proba(X_val)[:, 1]))

# --- SAVE ARTIFACTS ---
joblib.dump(rf, os.path.join(MODEL_DIR, "rf_supervised_sparse.joblib"))
joblib.dump(hasher, os.path.join(MODEL_DIR, "rf_hasher.joblib"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "rf_scaler.joblib"))

meta = {
    "features_hashed": X_final.shape[1],
    "rows": len(df),
    "model": "RandomForest (FeatureHasher)",
}
json.dump(meta, open(os.path.join(MODEL_DIR, "rf_sparse_info.json"), "w"), indent=2)

print("\n💾 Supervised RF model (sparse) retrained and saved successfully!")
