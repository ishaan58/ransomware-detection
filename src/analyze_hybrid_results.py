import os
import pandas as pd

DATA_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\data"
REPORT_DIR = r"C:\Users\victus\OneDrive - Manipal Academy of Higher Education\Documents\PROJECTS\ransomware-detector-main\reports"

# Load combined training data (has Label column)
combined = pd.read_csv(os.path.join(DATA_DIR, "combined_train.csv"))

# Load hybrid predictions
hybrid_pred = pd.read_csv(os.path.join(REPORT_DIR, "hybrid_predictions.csv"))

# Merge to add Label column
df = hybrid_pred.copy()
df["Label"] = combined["Label"].values[:len(df)]

print("=" * 80)
print("HYBRID DETECTION ANALYSIS")
print("=" * 80)

# Count total rows
total = len(df)
total_wannacry = (df["Label"] == 1).sum()
total_benign = (df["Label"] == 0).sum()

print(f"\nTotal rows analyzed: {total:,}")
print(f"  - WannaCry (Label=1): {total_wannacry:,}")
print(f"  - Benign (Label=0): {total_benign:,}")

# RF Results
rf_flagged_total = (df["rf_pred"] == 1).sum()
rf_correct = ((df["rf_pred"] == 1) & (df["Label"] == 1)).sum()
rf_false_pos = ((df["rf_pred"] == 1) & (df["Label"] == 0)).sum()

print(f"\nRandom Forest (RF) Results:")
print(f"  - Total flagged as malware: {rf_flagged_total}")
print(f"  - Correctly detected WannaCry: {rf_correct}")
print(f"  - False positives (benign flagged): {rf_false_pos}")
if total_wannacry > 0:
    print(f"  - Recall (% of WannaCry caught): {100 * rf_correct / total_wannacry:.2f}%")
if rf_flagged_total > 0:
    print(f"  - Precision (% of flags correct): {100 * rf_correct / rf_flagged_total:.2f}%")

# IF Results
if_flagged_total = (df["if_pred"] == 1).sum()
if_wannacry = ((df["if_pred"] == 1) & (df["Label"] == 1)).sum()
if_benign = ((df["if_pred"] == 1) & (df["Label"] == 0)).sum()

print(f"\nIsolation Forest (IF) Results:")
print(f"  - Total flagged as anomaly: {if_flagged_total}")
print(f"  - WannaCry rows flagged: {if_wannacry}")
print(f"  - Benign rows flagged: {if_benign}")

# Combined Results
combined_flagged = (df["combined_flag"] == 1).sum()
combined_correct = ((df["combined_flag"] == 1) & (df["Label"] == 1)).sum()

print(f"\nCombined (Both models agree) Results:")
print(f"  - Total flagged by BOTH: {combined_flagged}")
print(f"  - Correctly detected WannaCry: {combined_correct}")

print("\n" + "=" * 80)
print("SAMPLE OF RF-FLAGGED EVENTS (first 10):")
print("=" * 80)
rf_flagged_rows = df[df["rf_pred"] == 1][["Source", "Event ID", "rf_malware_prob", "Label"]].head(10)
print(rf_flagged_rows)

print("\n" + "=" * 80)
print("SAMPLE OF IF-FLAGGED EVENTS (first 10):")
print("=" * 80)
if_flagged_rows = df[df["if_pred"] == 1][["Source", "Event ID", "if_anomaly_score", "Label"]].head(10)
print(if_flagged_rows)

print("\n" + "=" * 80)
print("SUMMARY:")
print("=" * 80)
if total_wannacry > 0:
    print(f"RF detected {rf_correct}/{total_wannacry} WannaCry events ({100*rf_correct/total_wannacry:.1f}% recall)")
    print(f"IF detected {if_wannacry}/{total_wannacry} WannaCry events ({100*if_wannacry/total_wannacry:.1f}% recall)")
    print(f"Combined (both) detected {combined_correct}/{total_wannacry} WannaCry events ({100*combined_correct/total_wannacry:.1f}% recall)")
