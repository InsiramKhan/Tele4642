0.
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Generate synthetic flow data
n = 1000

df = pd.DataFrame({
    "src_port": np.random.randint(1024, 65535, size=n),
    "dst_port": np.random.randint(1, 1024, size=n),
    "proto": np.random.choice([6, 17], size=n),  # TCP, UDP
    "pkt_len": np.random.randint(60, 1500, size=n),
    "label": np.random.choice([0, 1], size=n, p=[0.85, 0.15])
})

# Add ICMP pings as benign (proto 1)
icmp_df = pd.DataFrame({
    "src_port": 0,
    "dst_port": 0,
    "proto": 1,
    "pkt_len": np.random.randint(60, 128, size=200),
    "label": 0
})

df = pd.concat([df, icmp_df], ignore_index=True)

# Train model
X = df[["src_port", "dst_port", "proto", "pkt_len"]]
y = df["label"]
X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, stratify=y)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Save
joblib.dump(clf, "rf_model.pkl")
print(" Model saved as rf_model.pkl")
