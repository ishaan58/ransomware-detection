# prepare_supervised_dataset.py
import os, glob, pandas as pd, numpy as np, argparse

DATA_DIR = r"C:\islabproject\data"

def load_real_benign(sample_n):
    # any CSV without 'test' and not synthetic supervised file
    candidates = [os.path.join(DATA_DIR, f) for f in os.listdir(DATA_DIR)
                  if f.endswith(".csv") and "test" not in f.lower() and "train_supervised_500k" not in f.lower()]
    dfs = []
    for p in candidates:
        df = pd.read_csv(p)
        dfs.append(df)
    combined = pd.concat(dfs, ignore_index=True).drop_duplicates().reset_index(drop=True)
    # assuming real logs are unlabeled or labeled 0
    combined["Label"] = combined.get("Label", 0)
    # take only benign rows
    benign = combined[combined["Label"] == 0]
    if len(benign) <= sample_n:
        return benign
    return benign.sample(n=sample_n, random_state=42).reset_index(drop=True)

def build(supervised_synth_path, sample_real=50000, out_path=None):
    synth = pd.read_csv(supervised_synth_path)
    # ensure Label column exists
    if "Label" not in synth.columns:
        # default assume inject_rate created Label
        raise SystemExit("Supervised synthetic file must contain a Label column.")
    real_sample = load_real_benign(sample_real)
    combined = pd.concat([synth, real_sample], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    if out_path is None:
        out_path = os.path.join(DATA_DIR, "supervised_train_final.csv")
    combined.to_csv(out_path, index=False)
    print(f"Wrote supervised training file with {len(combined):,} rows to {out_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--synth", required=True, help="Path to synthetic supervised CSV (ex: train_supervised_500k.csv)")
    parser.add_argument("--real_sample", type=int, default=50000, help="Number of real benign rows to include")
    parser.add_argument("--out", default=None, help="Output path")
    args = parser.parse_args()
    build(args.synth, sample_real=args.real_sample, out_path=args.out)