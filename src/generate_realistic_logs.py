"""
generate_realistic_logs.py

Generates realistic-looking Windows event-log CSV files with the schema:
Level,Date and Time,Source,Event ID,Task Category,EventDescription,Label

- Streams output to disk in chunks to support very large files (hundreds of thousands -> millions of rows).
- Injects a configurable percentage of "ransomware-like" events labeled as 1.
- Configurable seed, number of rows, output path(s).

Example usage (PowerShell):
python generate_realistic_logs.py --out_dir "C:\islabproject\data" --train_files train_part1.csv,train_part2.csv --rows 250000 --inject_rate 0.001

This would create for each train file 250k rows with 0.1% anomalies.
"""

import os
import csv
import argparse
import random
from datetime import datetime, timedelta
import itertools

# ----- realistic pools -----
LEVELS = ["Information", "Warning", "Error", "Critical", "Verbose"]
COMMON_SOURCES = [
    "Microsoft-Windows-Kernel-Power",
    "Microsoft-Windows-DNS-Client",
    "Microsoft-Windows-DriverFrameworks-UserMode",
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-TaskScheduler",
    "Microsoft-Windows-WindowsUpdateClient",
    "Microsoft-Windows-PrintService",
    "IntelSST-OED",
    "Netwtw14",
    "VMICTimeProvider",
    "McAfee Scheduled Task",
    "Windows Defender",
    "Service Control Manager",
    "Application Error",
    "User32",
]
COMMON_TASK_CATS = [
    "System", "Driver Load", "Service Control", "Security", "Application Error",
    "Network", "Power", "Task Scheduler", "Update Orchestrator", "PrintService"
]
# Common benign messages (for EventDescription)
BENIGN_MESSAGES = [
    "The description for Event ID {eid} from source {src} cannot be found.",
    "Name resolution for the name {host} timed out after none of the configured DNS servers responded.",
    "The system is entering Modern Standby Reason: Sleep, Hibernate, or Shutdown.",
    "The system is exiting Modern Standby Reason: Lid.",
    "Loaded driver {driver} successfully.",
    "The start type of the {svc} service was changed from demand start to disabled.",
    "Application {proc} crashed with fault code 0x{code:x}.",
    "Security audit succeeded for user {user}.",
    "User {user} logged on successfully.",
    "Device {dev} reported status STATUS_SUCCESS."
]

# Ransomware-like messages to inject (and keywords)
RANSOM_MESSAGES = [
    "vssadmin delete shadows /all /quiet",
    "cipher /w:c",
    "Suspicious encryption detected in folder C:\\Users\\{user}\\Documents",
    "Mass file write anomaly: creating many .encrypted files",
    "Unauthorized file rename / delete - potential ransomware behavior",
    "Detected process encryptor.exe modifying many files",
    "Shadow copy deletion attempted via vssadmin",
    "Ransom note file created: READ_ME.txt with ransom contact",
    "Encrypting files with AES256: rapid file writes detected",
]
RANSOM_KEYWORDS = ["vssadmin", "cipher", "encrypt", "encrypted", "ransom", "encryptor", "shadowcopy"]

# ----- helper generators -----
def random_time_range(start, end, n):
    """Generate n datetimes between start and end uniformly."""
    total = (end - start).total_seconds()
    for _ in range(n):
        offset = random.random() * total
        yield start + timedelta(seconds=offset)

def choose_benign_message(src, eid):
    templ = random.choice(BENIGN_MESSAGES)
    return templ.format(eid=eid, src=src, host=random.choice(["example.com","router.local","chatgpt.com"]), driver="intel_driver.sys", svc="McAfee Scheduled Task", proc=random.choice(["svchost.exe","explorer.exe"]), code=random.randint(1,0xFFFF), user=random.choice(["alice","bob","svc_update"]), dev="\\Device\\Harddisk0\\DR0")

def choose_ransom_message():
    templ = random.choice(RANSOM_MESSAGES)
    return templ.format(user=random.choice(["alice","bob","user1"]))

# ----- streaming writer -----
def stream_generate_csv(path, n_rows, inject_rate=0.001, start_dt=None, end_dt=None, seed=None, chunk=10000):
    """
    Stream `n_rows` rows to CSV path.
    inject_rate: fraction of rows labeled as ransomware
    chunk: number of rows buffered in memory before writing
    """
    if seed is not None:
        random.seed(seed)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    header = ["Level", "Date and Time", "Source", "Event ID", "Task Category", "EventDescription", "Label"]

    # time window defaults (last 30 days)
    if start_dt is None:
        end_dt = datetime.now() if end_dt is None else end_dt
        start_dt = end_dt - timedelta(days=30)
    elif end_dt is None:
        end_dt = start_dt + timedelta(days=30)

    # prepare generator of timestamps (not strictly ordered)
    # We'll draw per-chunk for randomness
    written = 0
    with open(path, "w", newline='', encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        while written < n_rows:
            to_write = min(chunk, n_rows - written)
            times = list(random_time_range(start_dt, end_dt, to_write))
            rows = []
            for t in times:
                # decide if this row is ransomware
                is_ransom = random.random() < inject_rate
                if is_ransom:
                    # pick rarer sources that might be suspicious (or reuse normal)
                    src = random.choice(["Microsoft-Windows-Security-Auditing", "SuspiciousProcess", "UnknownProcess", random.choice(COMMON_SOURCES)])
                    level = random.choice(["Error", "Critical", "Warning"])
                    task = random.choice(COMMON_TASK_CATS + ["File Encryption", "Process Behavior"])
                    eid = random.choice([4648, 4663, 1102, 7777, 9999, 8888])  # some IDs
                    msg = choose_ransom_message()
                    label = 1
                else:
                    src = random.choices(COMMON_SOURCES, weights=[5,5,3,6,3,4,2,2,3,1,2,3,2,2,2], k=1)[0]
                    level = random.choices(LEVELS, weights=[70,15,10,1,4], k=1)[0]
                    task = random.choice(COMMON_TASK_CATS)
                    # more realistic event ID sampling for common sources
                    if "Kernel-Power" in src:
                        eid = random.choice([41,42,109])
                    elif "DNS-Client" in src:
                        eid = random.choice([1014,1015])
                    elif "TaskScheduler" in task or "Task" in src:
                        eid = random.choice([106,200,201,7023])
                    else:
                        eid = random.randint(100, 8000)
                    msg = choose_benign_message(src, eid)
                    label = 0

                # Format date string in common Windows CSV style: dd-mm-yyyy HH:MM:SS or yyyy-mm-dd HH:MM:SS
                # We'll use ISO-like to be consistent: YYYY-MM-DD HH:MM:SS
                dt_str = t.strftime("%Y-%m-%d %H:%M:%S")
                rows.append([level, dt_str, src, eid, task, msg, label])

            writer.writerows(rows)
            written += to_write
            # progress print
            if written % max(1, (n_rows // 10)) == 0 or written == n_rows:
                print(f"[{os.path.basename(path)}] written {written}/{n_rows}")
    return path

# ----- orchestrator: create multiple files -----
def generate_multiple(out_dir, file_specs, inject_rate=0.001, seed=42, start_dt=None, end_dt=None):
    """
    file_specs: list of (filename, n_rows)
    """
    random.seed(seed)
    generated = []
    for fname, n in file_specs:
        out_path = os.path.join(out_dir, fname)
        print(f"Generating {out_path} ({n} rows) inject_rate={inject_rate}")
        p = stream_generate_csv(out_path, n_rows=n, inject_rate=inject_rate, start_dt=start_dt, end_dt=end_dt, seed=random.randint(0,2**31-1))
        generated.append(p)
    return generated

# ----- CLI -----
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate realistic Windows event-log CSVs (large, streamed).")
    parser.add_argument("--out_dir", type=str, default=r"C:\islabproject\data", help="Directory to write CSVs")
    parser.add_argument("--train_files", type=str, default="train_part1.csv", help="Comma-separated train filenames (created in out_dir)")
    parser.add_argument("--test_file", type=str, default="test_synthetic.csv", help="Single test filename")
    parser.add_argument("--rows", type=int, default=300000, help="Number of rows per train file (default 300k)")
    parser.add_argument("--test_rows", type=int, default=100000, help="Number of rows for test file (default 100k)")
    parser.add_argument("--inject_rate", type=float, default=0.005, help="Fraction of rows to inject as ransomware (default 0.005 = 0.5%)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--start", type=str, default=None, help="Start datetime (YYYY-MM-DD) optional")
    parser.add_argument("--end", type=str, default=None, help="End datetime (YYYY-MM-DD) optional")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    train_list = [s.strip() for s in args.train_files.split(",") if s.strip()]
    file_specs = [(fname, args.rows) for fname in train_list]

    sd = datetime.fromisoformat(args.start) if args.start else None
    ed = datetime.fromisoformat(args.end) if args.end else None

    # generate train files
    generated_train = generate_multiple(args.out_dir, file_specs, inject_rate=args.inject_rate, seed=args.seed, start_dt=sd, end_dt=ed)

    # generate test file
    test_path = os.path.join(args.out_dir, args.test_file)
    print(f"Generating test file {test_path} ({args.test_rows} rows)")
    stream_generate_csv(test_path, n_rows=args.test_rows, inject_rate=args.inject_rate, start_dt=sd, end_dt=ed, seed=args.seed + 1)

    print("All files generated:")
    for p in generated_train + [test_path]:
        print(" -", p)