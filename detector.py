import pandas as pd

THRESHOLD = 200

def detect_ddos():
    try:
        df = pd.read_csv("data/traffic_log.csv", on_bad_lines='skip')

        if df.empty:
            return []

        ip_counts = df["src_ip"].value_counts()

        suspicious = ip_counts[ip_counts > THRESHOLD]

        return suspicious.index.tolist()

    except Exception as e:
        print("Error reading file:", e)
        return []

if __name__ == "__main__":
    attackers = detect_ddos()
    print("Suspicious IPs:", attackers)
