import pandas as pd
import matplotlib.pyplot as plt

def show_graph():
    df = pd.read_csv("data/traffic_log.csv", header=None)
    df.columns = ["timestamp", "src_ip", "dst_ip", "protocol"]

    counts = df["src_ip"].value_counts().head(10)

    plt.figure()
    counts.plot(kind="bar")
    plt.title("Top Traffic Sources")
    plt.xlabel("Source IP")
    plt.ylabel("Packet Count")
    plt.show()

if __name__ == "__main__":
    show_graph()