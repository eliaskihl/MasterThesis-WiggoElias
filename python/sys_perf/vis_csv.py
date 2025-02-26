import pandas as pd
import matplotlib.pyplot as plt
def main(ids_performance_log, ids_name):
    df = pd.read_csv("python/sys_perf/suricata/logs/ids_performance_log.csv")
    print(df)

    # Extract the time, CPU usage, and memory usage columns

    time = df["Time"]
    cpu_usage = df["CPU_Usage (%)"]
    mem_usage = df["Memory_Usage (MB)"]

    plt.plot(time,cpu_usage, label="CPU Usage (%)")
    plt.plot(time,mem_usage, label="Memory Usage (MB)")
    plt.xlabel("Time")
    plt.ylabel("Usage")
    plt.title(f"{ids_name} System Performance")
    plt.legend()
    # save img as png
    plt.savefig(f"python/sys_perf/suricata/logs/{ids_name}_performance.png")



main("python/sys_perf/suricata/logs/ids_performance_log.csv", "Suricata")