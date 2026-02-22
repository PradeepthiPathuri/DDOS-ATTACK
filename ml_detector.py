import pandas as pd
from sklearn.ensemble import IsolationForest

def ml_detect():
    df = pd.read_csv("data/traffic_log.csv", header=None)
    df.columns = ["timestamp", "src_ip", "dst_ip", "protocol"]

    # Convert IP to numeric (simple encoding)
    df["src_ip_encoded"] = df["src_ip"].astype("category").cat.codes

    model = IsolationForest(contamination=0.05)
    df["anomaly"] = model.fit_predict(df[["src_ip_encoded"]])

    anomalies = df[df["anomaly"] == -1]
    return anomalies["src_ip"].unique()

if __name__ == "__main__":
    attackers = ml_detect()
    print("ML Detected Attackers:", attackers)
