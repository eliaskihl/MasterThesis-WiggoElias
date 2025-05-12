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
def vis(folder, num_cores):
    x_value = "Throughput"
    if folder == "latency":
        x_value = "Latency"
   
    speeds = []
    cpus = []
    mems = []
    drop_rates = []
    packet_analysis_rate = []
    total_packets_list = []
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
            cpus.append(cpu/num_cores)
            mems.append(mem)
            # TODO: Check if file exists before reading
            with open(f"./{folder}/{name}/perf_files/drop_rate_{speed}.txt", "r") as f:
               drop_rate = float(f.read())
               drop_rates.append(drop_rate)
            with open(f"./{folder}/{name}/perf_files/total_packets_{speed}.txt", "r") as f:
               total_packets = float(f.read())
               total_packets_list.append(total_packets)
               packet_analysis_rate.append(total_packets/60)

        dfs[name] = pd.DataFrame({x_value:speeds, "CPU_Usage":cpus, "Memory_Usage":mems, "Drop_Rate":drop_rates, 
                                  "Packet_Analysis_Rate":packet_analysis_rate, "Total_Packets_Sent":total_packets_list})
        # Clear
        speeds = []
        cpus = []
        mems = []
        drop_rates = []
        total_packets_list = []
        packet_analysis_rate = []

    df_sur = dfs["suricata"]
    df_snort = dfs["snort"]
    df_zeek = dfs["zeek"]
    print(df_sur)
    print(df_snort)
    print(df_zeek)
    # Merge based on "Speed" / "Latency"
    df = pd.merge(df_sur, df_snort, on=x_value, suffixes=('_suricata', '_snort'))
    print(df)
    print("")
    df = pd.merge(df_zeek, df, on=x_value, suffixes=('_zeek', ''))
    print(df)
    # Change name of column "CPU" to "CPU_zeek"
    df.rename(columns={"CPU_Usage":"CPU_Usage_zeek", "Memory_Usage":"Memory_Usage_zeek", "Drop_Rate":"Drop_Rate_zeek", 
                       "Packet_Analysis_Rate":"Packet_Analysis_Rate_zeek", "Total_Packets_Sent":"Total_Packets_Sent_zeek"}, inplace=True)
    print(df)
    # Save dataframe in a folder
    

    if not os.path.exists(f"../../tables/{folder}/"):
        os.makedirs(f"../../tables/{folder}/")
    df.to_csv(f"../../tables/{folder}/syseval.csv")


    if not os.path.exists(f"../../img/{folder}/"):
        os.makedirs(f"../../img/{folder}/")
        
    
    width,height = 8,6
    x_title = "Throughput (Mbps)"
    if folder == "latency":
        x_title = "Latency (us)"
    df.plot(x=x_value, y=["CPU_Usage_suricata", "CPU_Usage_snort","CPU_Usage_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "snort", "Zeek"])
    plt.title(f"Average CPU Usage")
    plt.ylabel("CPU Usage (%)")
    plt.xlabel(f"{x_title}")
    print("Saving plot CPU")
    plt.savefig(f"../../img/{folder}/cpu.png")
    plt.clf()  # Clear the figure

    df.plot(x=x_value, y=["Memory_Usage_suricata", "Memory_Usage_snort","Memory_Usage_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort", "Zeek"])
    plt.title(f"Average Memory Usage")
    plt.ylabel("Memory Usage (%)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Memory")
    plt.savefig(f"../../img/{folder}/memory.png")
    plt.clf()  # Clear the figure

    df.plot(x=x_value, y=["Drop_Rate_suricata", "Drop_Rate_snort","Drop_Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort", "Zeek"])
    plt.title(f"Drop Rate")
    plt.ylabel("Drop Rate (%)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Drop Rate")
    plt.savefig(f"../../img/{folder}/drop_rate.png")
    plt.clf()  # Clear the figure

    df.plot(x=x_value, y=["Packet_Analysis_Rate_suricata", "Packet_Analysis_Rate_snort","Packet_Analysis_Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort", "Zeek"])
    plt.title(f"Packet Analysis")
    plt.ylabel("Packet Analysis Rate (packets/minute)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Packet Analysis Rate")
    plt.savefig(f"../../img/{folder}/packet_analysis_rate.png")
    plt.clf()  # Clear the figure

    df.plot(x=x_value, y=["Total_Packets_Sent_suricata", "Total_Packets_Sent_snort","Total_Packets_Sent_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort", "Zeek"])
    plt.title(f"Total Packets Sent")
    plt.ylabel("Total Packets Sent (packets)")
    plt.xlabel(f"{x_title}")
    print("Saving plot Total Packets Sent")
    plt.savefig(f"../../img/{folder}/total_packets_sent.png")
    plt.clf()  # Clear the figure

def visualize(folder,num_cores):
    # Folder is the type, throughput or latency
    start = time.time()

    vis(folder,int(num_cores))
    end = time.time()
    print("Runtime:",end-start)


