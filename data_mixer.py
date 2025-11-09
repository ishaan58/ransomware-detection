import pandas as pd

# Load all logs
wc = pd.read_csv('data/wannacry.csv')
wc['Label'] = 1
x = pd.read_csv('data/x.csv')
x['Label'] = 0
tanay = pd.read_csv('data/tanay_logs.csv')
tanay['Label'] = 0
keshav = pd.read_csv('data/keshav_logs.csv')
keshav['Label'] = 0

# Consistent columns (fill missing cols as needed)
all_data = pd.concat([wc, x, tanay, keshav], ignore_index=True)
all_data = all_data.fillna('NA')  # fill blanks if any

# Save out
all_data.to_csv('data/combined_train.csv', index=False)
