"""
evaluate_overfitting.py
-----------------------
Evaluates the regularized RF (sparse) model for overfitting,
generating learning curves, CV boxplots, and confusion matrices.
"""
import os, joblib, numpy as np, pandas as pd
from scipy import sparse
from sklearn.model_selection import train_test_split, cross_val_score, learning_curve
from sklearn.metrics import (
    roc_auc_score, f1_score, classification_report, confusion_matrix
)
import matplotlib.pyplot as plt, seaborn as sns

# --- Paths ---
DATA_DIR = r"C:\islabproject\data"
MODEL_DIR = r"C:\islabproject\models"
REPORT_DIR = r"C:\islabproject\reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# --- Load model and preprocessors ---
model_path = os.path.join(MODEL_DIR, "rf_supervised_sparse.joblib")
if not os.path.exists(model_path):
    model_path = os.path.join(MODEL_DIR, "rf_supervised.joblib")
model = joblib.load(model_path)
hasher = joblib.load(os.path.join(MODEL_DIR, "rf_hasher.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "rf_scaler.joblib"))
print(f"✅ Loaded model: {os.path.basename(model_path)}")

# --- Load supervised data ---
df = pd.read_csv(os.path.join(DATA_DIR, "supervised_train_final.csv"))
y = df["Label"].astype(int)
df = df.drop(columns=["Label"])

# --- Safe feature engineering ---
for col in ["Level", "Source", "Task Category", "Event ID", "Date and Time"]:
    if col not in df.columns:
        df[col] = "NA"

df["Event ID"] = pd.to_numeric(df["Event ID"], errors="coerce").fillna(0)
df["Date and Time"] = pd.to_datetime(df["Date and Time"], errors="coerce")
df["hour"] = df["Date and Time"].dt.hour.fillna(0).astype(int)
df["dayofweek"] = df["Date and Time"].dt.dayofweek.fillna(0).astype(int)
df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)

cat_cols = ["Level", "Source", "Task Category"]
expected_num_cols = getattr(scaler, "feature_names_in_", ["Event ID"])
df_num = df[[c for c in expected_num_cols if c in df.columns]]
X_num = scaler.transform(df_num)
cat_dicts = df[cat_cols].astype(str).to_dict(orient="records")
X_cat = hasher.transform(cat_dicts)
X = sparse.hstack([X_cat, sparse.csr_matrix(X_num.astype(np.float32))]).tocsr()
print(f"✅ Feature matrix ready: {X.shape}")

# --- Split ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# --- Evaluate ---
print("Evaluating performance...")
y_train_pred = model.predict(X_train)
y_test_pred = model.predict(X_test)
y_train_prob = model.predict_proba(X_train)[:, 1]
y_test_prob = model.predict_proba(X_test)[:, 1]

train_auc = roc_auc_score(y_train, y_train_prob)
test_auc = roc_auc_score(y_test, y_test_prob)

print(f"Train AUC: {train_auc:.6f} | Test AUC: {test_auc:.6f}")
print("\nClassification report (test):\n", classification_report(y_test, y_test_pred))

# --- CV Boxplot ---
f1_scores = cross_val_score(model, X, y, cv=5, scoring="f1", n_jobs=-1)
roc_scores = cross_val_score(model, X, y, cv=5, scoring="roc_auc", n_jobs=-1)
plt.figure(figsize=(6,4))
sns.boxplot(data=[f1_scores, roc_scores])
plt.xticks([0,1], ["F1", "ROC-AUC"])
plt.title("Cross-validation Score Distribution")
plt.savefig(os.path.join(REPORT_DIR, "cv_boxplot_sparse.png"), bbox_inches="tight")
plt.close()

# --- Learning curve ---
train_sizes, train_scores, test_scores = learning_curve(
    model, X, y, cv=3, scoring="roc_auc", n_jobs=-1,
    train_sizes=np.linspace(0.1, 1.0, 5)
)
plt.figure(figsize=(6,4))
plt.plot(train_sizes, np.mean(train_scores, axis=1), label="Train")
plt.plot(train_sizes, np.mean(test_scores, axis=1), label="Test")
plt.xlabel("Training Samples")
plt.ylabel("ROC-AUC")
plt.legend()
plt.title("Learning Curve (Sparse RF)")
plt.grid(True)
plt.savefig(os.path.join(REPORT_DIR, "learning_curve_sparse.png"), bbox_inches="tight")
plt.close()

# --- Confusion Matrices ---
cm_train = confusion_matrix(y_train, y_train_pred)
cm_test = confusion_matrix(y_test, y_test_pred)
fig, ax = plt.subplots(1, 2, figsize=(10,4))
sns.heatmap(cm_train, annot=True, fmt="d", ax=ax[0], cmap="Blues")
ax[0].set_title("Train Confusion Matrix")
sns.heatmap(cm_test, annot=True, fmt="d", ax=ax[1], cmap="Reds")
ax[1].set_title("Test Confusion Matrix")
plt.savefig(os.path.join(REPORT_DIR, "confusion_matrices_sparse.png"), bbox_inches="tight")
plt.close()

# --- Save report summary ---
with open(os.path.join(REPORT_DIR, "train_test_report_sparse.txt"), "w") as f:
    f.write(f"Train AUC: {train_auc}\nTest AUC: {test_auc}\n")
    f.write("\nClassification Report (Test):\n")
    f.write(classification_report(y_test, y_test_pred))

print(f"✅ Overfitting analysis complete.\nReports & visuals saved to: {REPORT_DIR}")
