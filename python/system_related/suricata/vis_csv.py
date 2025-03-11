import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
def viz(ids_performance_log, ids_name,speed):
    df = pd.read_csv(ids_performance_log)
    print(df)

    # Extract the time, CPU usage, and memory usage columns
    
    # filter out rows that have cpu_usage between 0.0 and 2.0
    df = df[df["CPU_Usage (%)"] > 5.0]
    # Extract seconds part of time "2025-02-26 12:39:22"
    df["Time"] = df["Time"].apply(lambda x: x.split(":")[-1])
    time = df["Time"]
    
    cpu_usage = df["CPU_Usage (%)"]
    mem_usage = df["Memory_Usage (%)"]

    # Round decimals of mem_usage array
    mem_usage = np.round(mem_usage, 1)
    indices = np.arange(len(time))
    bar_width = 0.35
    # Print max values
    print(f"Max CPU usage: {max(cpu_usage)}%")
    print(f"Max memory usage: {max(mem_usage)}%")
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
    plt.savefig(f"img/{ids_name}_performance{speed}.png")



# viz("python/system_related/suricata/logs/ids_performance_log200.csv", "IDS", 200)
def calc_mean(ids_performance_log):
    df = pd.read_csv(ids_performance_log)    
    # filter out rows that have cpu_usage between 0.0 and 2.0
    df = df[df["CPU_Usage (%)"] > 2.0]
    # Extract seconds part of time "2025-02-26 12:39:22"
    
    cpu_usage = df["CPU_Usage (%)"]
    mem_usage = df["Memory_Usage (%)"]
    # take the average of the cpu_usage and mem_usage
    cpu_usage = cpu_usage.mean()
    mem_usage = np.round(mem_usage.mean(),1)
    # Round decimals of mem_usage array
    return cpu_usage, mem_usage


def visualize(ids_name):
    speeds = []
    cpus = []
    mems = []
    files = glob.glob("python/system_related/suricata/logs/ids_performance_log*.csv")
    for file in files:
        speeds.append(int(file.split("_")[-1].split(".")[0]))
        cpu, mem = calc_mean(file)
        cpus.append(cpu)
        mems.append(mem)

    # Create dataframe
    df = pd.DataFrame({
        "Speed": speeds,
        "CPU": cpus,
        "Memory": mems
    })
    # order dataframe by speed
    df = df.sort_values(by="Speed")    
    

    indices = np.arange(len(df["Speed"]))
    bar_width = 0.35
    
    # Plot CPU usage bars
    plt.bar(indices - bar_width / 2, df["CPU"], width=bar_width, label="CPU")

    # Plot memory usage bars
    plt.bar(indices + bar_width / 2, df["Memory"], width=bar_width, label="Memory")
    plt.xlabel("Speed (Mbit/s)")
    plt.ylabel("Usage (%)")
    plt.xticks(indices, df["Speed"], rotation=90)
    plt.title(f"{ids_name} System Performance")
    plt.legend()
    # Save image
    print("Save image as png")
    plt.savefig(f"img/{ids_name}_performance_test.png")
""" 
ta ut average for varje run (speed) och plotta en barplot med speed som x-axel och cpu och mem som y-axel
"""

