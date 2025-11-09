import os, joblib, json
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import FeatureHasher
from sklearn.preprocessing import StandardScaler
from scipy import sparse

DATA_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\data"
MODEL_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\models"
os.makedirs(MODEL_DIR, exist_ok=True)

# Load combined training data
df = pd.read_csv(os.path.join(DATA_DIR, "combined_train.csv"))
print(f"✅ Loaded {len(df):,} rows from combined_train.csv.")

# ONLY use BENIGN rows for Isolation Forest training
benign = df[df["Label"] == 0].copy()
print(f"✅ Using {len(benign):,} benign rows for IF training.")

# Feature engineering
cat_cols = [c for c in benign.columns if benign[c].dtype == object and c != "Label"]
num_cols = [c for c in benign.columns if c not in cat_cols and c != "Label"]

for c in num_cols:
    benign[c] = pd.to_numeric(benign[c], errors="coerce").fillna(0)

print(f"Detected {len(cat_cols)} categorical and {len(num_cols)} numeric columns.")

# Feature hashing for categorical
hasher = FeatureHasher(n_features=512, input_type="dict")
cat_dicts = benign[cat_cols].astype(str).to_dict(orient="records")
X_cat = hasher.transform(cat_dicts)

# Scale numeric
scaler = StandardScaler()
X_num = scaler.fit_transform(benign[num_cols])

X = sparse.hstack([X_cat, sparse.csr_matrix(X_num)]).tocsr()
print(f"✅ Final feature matrix: {X.shape}")

# Train Isolation Forest
iforest = IsolationForest(
    contamination=0.001,  # Expect ~0.1% contamination in benign set
    random_state=42,
    n_jobs=-1,
    n_estimators=200
)
iforest.fit(X)
print("✅ Isolation Forest trained on benign data.")

# Save artifacts
joblib.dump(iforest, os.path.join(MODEL_DIR, "isolation_forest_retrained.joblib"))
joblib.dump(hasher, os.path.join(MODEL_DIR, "if_hasher.joblib"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "if_scaler.joblib"))

meta = {"features": X.shape[1], "rows": len(benign), "model": "IsolationForest"}
json.dump(meta, open(os.path.join(MODEL_DIR, "if_info.json"), "w"), indent=2)

print("\n💾 Isolation Forest model saved successfully!")
