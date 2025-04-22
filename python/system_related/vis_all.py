import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import os
import time
import argparse
import re

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
import os

def sort_directory(path, by='name', descending=False):
    """
    Sorts files in a directory by name, size, or modification time.

    Args:
        path (str): Path to the directory.
        by (str): Sort key - 'name', 'size', or 'mtime'.
        descending (bool): If True, sort in descending order.

    Returns:
        List[str]: Sorted list of filenames.
    """
    if not os.path.isdir(path):
        raise ValueError(f"Path '{path}' is not a valid directory.")

    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]

    if by == 'name':
        key_func = lambda f: f.lower()
    elif by == 'size':
        key_func = lambda f: os.path.getsize(os.path.join(path, f))
    elif by == 'mtime':
        key_func = lambda f: os.path.getmtime(os.path.join(path, f))
    else:
        raise ValueError("Sort 'by' must be one of: 'name', 'size', 'mtime'")

    return sorted(files, key=key_func, reverse=descending)

def natural_sort(file_list):
    return sorted(file_list, key=lambda s: [int(t) if t.isdigit() else t.lower()
                                            for t in re.split(r'(\d+)', s)])
def visualize(folder):
    speeds = []
    cpus = []
    mems = []
    drop_rates = []
    packet_analysis_rate = []
    # Create empty dataframe
    dfs = {}
    print("Current Working Directory:", os.getcwd())
    for name in ["suricata","snort","zeek"]:
        files = sorted(glob.glob(f"./{folder}/{name}/perf_files/ids_performance_log*.csv"))
        files = natural_sort(files)
    
        for file in files:
            print("File", file)
            speed = (int(file.split("_")[-1].split(".")[0]))
            speeds.append(speed)
            cpu, mem = calc_mean(file)
            cpus.append(cpu)
            mems.append(mem)
            # TODO: Check if file exists before reading
            with open(f"./{folder}/{name}/perf_files/drop_rate_{speed}.txt", "r") as f:
               drop_rate = float(f.read())
               drop_rates.append(drop_rate)
            with open(f"./{folder}/{name}/perf_files/total_packets_{speed}.txt", "r") as f:
               total_packets = float(f.read())
               packet_analysis_rate.append(total_packets/60)
        dfs[name] = pd.DataFrame({"Speed":speeds, "CPU":cpus, "Memory":mems, "Drop Rate":drop_rates, "Packet Analysis Rate":packet_analysis_rate, "Total Packets Sent":total_packets})
        # Clear
        speeds = []
        cpus = []
        mems = []
        drop_rates = []
        packet_analysis_rate = []

    df_sur = dfs["suricata"]
    df_snort = dfs["snort"]
    df_zeek = dfs["zeek"]
    print(df_sur)
    print(df_snort)
    print(df_zeek)
    # Merge based on "Speed"
    df = pd.merge(df_sur, df_snort, on="Speed", suffixes=('_suricata', '_snort'))
    print(df)
    print("")
    df = pd.merge(df_zeek, df, on="Speed", suffixes=('_zeek', ''))
    print(df)
    # Change name of column "CPU" to "CPU_zeek"
    df.rename(columns={"CPU":"CPU_zeek", "Memory":"Memory_zeek", "Drop Rate":"Drop Rate_zeek", "Packet Analysis Rate":"Packet Analysis Rate_zeek", "Total Packets Sent":"Total Packets Sent_zeek"}, inplace=True)
    print(df)
    
    if not os.path.exists(f"../../img/{folder}/"):
        os.mkdir(f"../../img/{folder}/")
    
    width,height = 8,6
    x_title = "Throughput (Mbps)"
    if folder == "latency":
        x_title = "Latency (qs)"
    df.plot(x="Speed", y=["CPU_suricata", "CPU_snort","CPU_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "snort", "Zeek"])
    plt.title(f"Average CPU Usage")
    plt.ylabel("CPU (%)")
    plt.xlabel(f"{x_title}")
    print("Saving plot CPU")
    plt.savefig(f"../../img/{folder}/cpu.png")
    plt.clf()  # Clear the figure

    df.plot(x="Speed", y=["Memory_suricata", "Memory_snort","Memory_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "snort", "Zeek"])
    plt.title(f"Average Memory Usage")
    plt.ylabel("Memory (%)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Memory")
    plt.savefig(f"../../img/{folder}/memory.png")
    plt.clf()  # Clear the figure

    df.plot(x="Speed", y=["Drop Rate_suricata", "Drop Rate_snort","Drop Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "snort", "Zeek"])
    plt.title(f"Drop Rate")
    plt.ylabel("Drop Rate (%)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Drop Rate")
    plt.savefig(f"../../img/{folder}/drop_rate.png")
    plt.clf()  # Clear the figure

    df.plot(x="Speed", y=["Packet Analysis Rate_suricata", "Packet Analysis Rate_snort","Packet Analysis Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "snort", "Zeek"])
    plt.title(f"Packet Analysis")
    plt.ylabel("Packet Analysis Rate (packets/seconds)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Packet Analysis Rate")
    plt.savefig(f"../../img/{folder}/packet_analysis_rate.png")
    plt.clf()  # Clear the figure

    df.plot(x="Speed", y=["Total Packets Sent_suricata", "Total Packets Sent_snort","Total Packets Sent_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "snort", "Zeek"])
    plt.title(f"Total Packets Sent")
    plt.ylabel("Total Packets Sent (packets)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Total Packets Sent")
    plt.savefig(f"../../img/{folder}/packet_analysis_rate.png")
    plt.clf()  # Clear the figure

def main():
    start = time.time()
    print("Current Working Directory:", os.getcwd())
    # generate_pcap_file_latency_eval(140000) # Similar amount to {folder} measurments, could be calculated by checking loop size and smallFlows.pcap length.
    parser = argparse.ArgumentParser(description="Run system performance evaluation on all IDSs with set packet size.")
    parser.add_argument("folder", help="Folder name, must be regular, parallel or latency")
    args = parser.parse_args()
    visualize(args.folder)
    end = time.time()
    print("Runtime:",end-start)

if __name__ == "__main__":
    main()

