import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
from suricata.vis_csv import calc_mean
def visualize():


    # Suricata
    speeds = []
    cpus = []
    mems = []
    names = []
    for name in ["suricata","snort"]:
        sur_files = glob.glob(f"python/system_related/{name}/logs/ids_performance_log*.csv")
        for file in sur_files:
            speeds.append(int(file.split("_")[-1].split(".")[0]))
            cpu, mem = calc_mean(file)
            cpus.append(cpu)
            mems.append(mem)
            names.append("{name}")

        # Create dataframe
        df = pd.DataFrame({
            "Speed": speeds,
            "CPU": cpus,
            "Memory": mems,
            "Name": names
        })
    # order dataframe by speed
    
    
    df_sur = df[df["Name"] == "suricata"]
    df_snort = df[df["Name"] == "snort"]
    df_sur = df.sort_values(by="Speed")    
    df_snort = df.sort_values(by="Speed")    
    indices = np.arange(len(df["Speed"]))
    bar_width = 0.35
    if df_snort["Speed"] != df_sur["Speed"]:
        print("Speeds are not equal, exit...")
        exit(0)
    # Plot CPU usage bars
    plt.bar(indices - bar_width / 2, df_sur["CPU"], width=bar_width, label=name)

    # Plot memory usage bars
    plt.bar(indices + bar_width / 2, df_snort["CPU"], width=bar_width, label=name)
    plt.xlabel("Speed (Mbit/s)")
    plt.ylabel("CPU Usage (%)")
    plt.xticks(indices, df["Speed"], rotation=90)
    plt.title("System Performance")
    plt.legend()
    # Save image
    print("Save image as png")
    plt.savefig(f"img/performane.png")
    # Plot CPU usage bars
    plt.bar(indices - bar_width / 2, df_sur["Memory"], width=bar_width, label="Suricata")

    # Plot memory usage bars
    plt.bar(indices + bar_width / 2, df_snort["Memory"], width=bar_width, label="Snort")
    plt.xlabel("Speed (Mbit/s)")
    plt.ylabel("CPU Usage (%)")
    plt.xticks(indices, df["Speed"], rotation=90)
    plt.title("System Performance")
    plt.legend()
    # Save image
    print("Save image as png")
    plt.savefig(f"img/performane.png")
""" 
ta ut average for varje run (speed) och plotta en barplot med speed som x-axel och cpu och mem som y-axel
"""
