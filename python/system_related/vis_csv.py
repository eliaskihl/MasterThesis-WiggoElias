import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
def main(ids_performance_log, ids_name):
    df = pd.read_csv("python/system_related/suricata/logs/ids_performance_log.csv")
    print(df)

    # Extract the time, CPU usage, and memory usage columns
    # extarct seconds part of time "2025-02-26 12:39:22"
    df["Time"] = df["Time"].apply(lambda x: x.split(":")[-1])
    time = df["Time"]
    print(time)
    cpu_usage = df["CPU_Usage (%)"]
    mem_usage = df["Memory_Usage (%)"]
    indices = np.arange(len(time))
    bar_width = 0.35
    # Plot CPU usage bars
    plt.bar(indices - bar_width / 2, cpu_usage, width=bar_width, label="CPU")

    # Plot memory usage bars
    plt.bar(indices + bar_width / 2, mem_usage, width=bar_width, label="Memory")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Usage (%)")
    plt.xticks(indices, time, rotation=90)
    plt.title(f"{ids_name} System Performance")
    plt.legend()
    # Save image
    print("Save image as png")
    plt.savefig(f"python/system_related/suricata/logs/{ids_name}_performance.png")



main("python/system_related/suricata/logs/ids_performance_log.csv", "Suricata")