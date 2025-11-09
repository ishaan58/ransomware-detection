"""
retrain_real_logs.py
====================

Retrains an IsolationForest model using all logs in C:\islabproject\data.
Excludes files with 'test' in the name.

Saves model artifacts in C:\islabproject\models:
  hasher.joblib, scaler.joblib, pca.joblib, isolation_forest.joblib, model_info.json
"""

import os, glob, shutil, json
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import FeatureHasher
import joblib

# -------- CONFIG --------
DATA_DIR = r"C:\islabproject\data"
MODEL_DIR = r"C:\islabproject\models"
os.makedirs(MODEL_DIR, exist_ok=True)

# Find all CSVs except test files
TRAIN_FILES = [f for f in glob.glob(os.path.join(DATA_DIR, "*.csv")) if "test" not in os.path.basename(f).lower()]
print(f"📂 Training on {len(TRAIN_FILES)} files:")
for f in TRAIN_FILES:
    print("  -", os.path.basename(f))

if not TRAIN_FILES:
    raise SystemExit("❌ No training CSV files found.")

# -------- BACKUP OLD MODELS --------
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
backup_dir = os.path.join(MODEL_DIR, f"backup_{timestamp}")
os.makedirs(backup_dir, exist_ok=True)
for f in os.listdir(MODEL_DIR):
    if f.endswith((".joblib", ".pkl", ".json")):
        shutil.move(os.path.join(MODEL_DIR, f), os.path.join(backup_dir, f))
print(f"🧹 Old models moved to {backup_dir}")

# -------- LOAD DATA --------
dfs = [pd.read_csv(f) for f in TRAIN_FILES]
df = pd.concat(dfs, ignore_index=True).drop_duplicates().reset_index(drop=True)
print(f"✅ Loaded {len(df):,} total rows from {len(TRAIN_FILES)} files.")

# -------- BASIC CLEANING --------
for col in ["Level", "Date and Time", "Source", "Event ID", "Task Category"]:
    if col not in df.columns:
        df[col] = "NA"

df["Event ID"] = pd.to_numeric(df["Event ID"], errors="coerce").fillna(0).astype(int)
df["Date and Time"] = pd.to_datetime(df["Date and Time"], errors="coerce")
df["hour"] = df["Date and Time"].dt.hour.fillna(0).astype(int)
df["dayofweek"] = df["Date and Time"].dt.dayofweek.fillna(0).astype(int)

cat_cols = ["Level", "Source", "Task Category"]
num_cols = ["Event ID", "hour", "dayofweek"]

# -------- HASH + SCALE --------
print("🔧 Hashing + scaling features...")
cat_dicts = df[cat_cols].astype(str).to_dict(orient='records')
hasher = FeatureHasher(n_features=256, input_type='dict')
X_cat = hasher.transform(cat_dicts).toarray()
scaler = StandardScaler()
X_num = scaler.fit_transform(df[num_cols])
X = np.hstack([X_cat, X_num])
print("✅ Feature matrix:", X.shape)

# -------- PCA --------
print("🌀 Applying PCA (20 components)...")
pca = PCA(n_components=min(20, X.shape[1]), random_state=42)
X = pca.fit_transform(X)

# -------- TRAIN MODEL --------
if "Label" in df.columns:
    benign = df[df["Label"] == 0]
    print(f"Using {len(benign):,} benign rows for training (Label=0).")
    X_train = X[benign.index]
else:
    X_train = X
    print("No Label column found — training on full dataset.")

model = IsolationForest(
    n_estimators=400,
    contamination=0.02,
    random_state=42,
    n_jobs=-1
)
print("🚀 Training IsolationForest...")
model.fit(X_train)
print("✅ Model trained successfully.")

# -------- SAVE COMPONENTS --------
joblib.dump(hasher, os.path.join(MODEL_DIR, "hasher.joblib"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
joblib.dump(pca, os.path.join(MODEL_DIR, "pca.joblib"))
joblib.dump(model, os.path.join(MODEL_DIR, "isolation_forest.joblib"))

meta = {
    "trained_on": [os.path.basename(f) for f in TRAIN_FILES],
    "timestamp": timestamp,
    "hasher_features": 256,
    "pca_components": pca.n_components_,
    "n_estimators": 400,
    "contamination": 0.02
}
json.dump(meta, open(os.path.join(MODEL_DIR, "model_info.json"), "w"), indent=2)
print("💾 Saved model artifacts to", MODEL_DIR)
print("🎉 Training complete.")
