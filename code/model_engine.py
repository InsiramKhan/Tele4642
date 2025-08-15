import joblib
import pandas as pd

# Load model
model = joblib.load("rf_model.pkl")

def classify_flow(flow_features):
    try:
        # Construct a DataFrame with the correct feature names
        input_df = pd.DataFrame([{
            "proto": flow_features["proto"],
            "pkt_len": flow_features["pkt_len"],
            "src_port": flow_features["src_port"],
            "dst_port": flow_features["dst_port"]
        }])

        # Predict class (0 = benign, 1 = malicious)
        prediction = model.predict(input_df)[0]

        return "malicious" if prediction == 1 else "benign"

    except Exception as e:
        print(f"[ML ERROR] classify_flow failed: {e}")
        return "unknown"
