import pandas as pd
import numpy as np
from faker import Faker
fake = Faker()
np.random.seed(10)
N_benign = 100
N_malware = 40

NUMERIC_COLS = ["Event ID", "hour", "dayofweek", "is_offhours"]
# Always create numeric columns as integers

def rand_level():
    return np.random.choice(["Information", "Warning", "Critical", "Error"])
def rand_source(is_mal):
    return "ransomware.exe" if is_mal else fake.word()
def rand_task(is_mal):
    return "Trojan" if is_mal else fake.word()
def rand_eid(is_mal):
    return int(np.random.randint(4000, 5000)) if is_mal else int(np.random.randint(1000, 2000))
def rand_date():
    dt = fake.date_time_this_year()
    return dt.strftime("%Y-%m-%d %H:%M:%S")
def rand_hour():
    return int(np.random.randint(0,24))
def rand_day():
    return int(np.random.randint(0,7))
def rand_offhours(hour):
    return int(hour < 6 or hour > 22)

benign = []
for _ in range(N_benign):
    hour = rand_hour()
    benign.append({
        "Level": rand_level(),
        "Source": rand_source(False),
        "Task Category": rand_task(False),
        "Event ID": rand_eid(False),
        "Date and Time": rand_date(),
        "hour": hour,
        "dayofweek": rand_day(),
        "is_offhours": rand_offhours(hour),
        "label": 0
    })
malware = []
for _ in range(N_malware):
    hour = rand_hour()
    malware.append({
        "Level": rand_level(),
        "Source": rand_source(True),
        "Task Category": rand_task(True),
        "Event ID": rand_eid(True),
        "Date and Time": rand_date(),
        "hour": hour,
        "dayofweek": rand_day(),
        "is_offhours": rand_offhours(hour),
        "label": 1
    })
logs = benign + malware
np.random.shuffle(logs)
df = pd.DataFrame(logs)
df = df[["Level", "Source", "Task Category", "Event ID", "Date and Time", "hour", "dayofweek", "is_offhours", "label"]]  # enforce column order
df.to_csv("data/test_fake_labeled.csv", index=False)
print("Fake labeled log file created as data/test_fake_labeled.csv")
