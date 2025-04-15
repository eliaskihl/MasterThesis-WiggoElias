import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import os

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

def visualize(size):
    speeds = []
    cpus = []
    mems = []
    drop_rates = []
    packet_analysis_rate = []
    # Create empty dataframe
    dfs = {}
    print("Current Working Directory:", os.getcwd())
    for name in ["suricata","snort3","zeek"]:
        sur_files = glob.glob(f"./{name}/perf_files_{size}/ids_performance_log*.csv")
       
        for file in sur_files:
            print("File", file)
            speed =(int(file.split("_")[-1].split(".")[0]))
            speeds.append(speed)
            cpu, mem = calc_mean(file)
            cpus.append(cpu)
            mems.append(mem)
            # TODO: Check if file exists before reading
            with open(f"./{name}/perf_files_{size}/drop_rate_{speed}.txt", "r") as f:
               drop_rate = float(f.read())
               drop_rates.append(drop_rate)
            with open(f"./{name}/perf_files_{size}/total_packets_{speed}.txt", "r") as f:
               total_packets = float(f.read())
               packet_analysis_rate.append(total_packets/60)
        dfs[name] = pd.DataFrame({"Speed":speeds, "CPU":cpus, "Memory":mems, "Drop Rate":drop_rates, "Packet Analysis Rate":packet_analysis_rate})
        # Clear
        speeds = []
        cpus = []
        mems = []
        drop_rates = []
        packet_analysis_rate = []

    df_sur = dfs["suricata"]
    df_snort = dfs["snort3"]
    df_zeek = dfs["zeek"]
    print(df_sur)
    print(df_snort)
    print(df_zeek)
    # Merge based on "Speed"
    df = pd.merge(df_sur, df_snort, on="Speed", suffixes=('_suricata', '_snort3'))
    print(df)
    print("")
    df = pd.merge(df_zeek, df, on="Speed", suffixes=('_zeek', ''))
    print(df)
    # Change name of column "CPU" to "CPU_zeek"
    df.rename(columns={"CPU":"CPU_zeek", "Memory":"Memory_zeek", "Drop Rate":"Drop Rate_zeek", "Packet Analysis Rate":"Packet Analysis Rate_zeek"}, inplace=True)
    print(df)
    
    if not os.path.exists(f"../../img/{size}/"):
        os.mkdir(f"../../img/{size}")
    
    width,height = 8,6
    df.plot(x="Speed", y=["CPU_suricata", "CPU_snort3","CPU_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title(f"CPU Usage : Snaplen: {size}")
    plt.ylabel("CPU (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot CPU")
    plt.savefig(f"../../img/{size}/cpu.png")

    df.plot(x="Speed", y=["Memory_suricata", "Memory_snort3","Memory_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title(f"Memory Usage : Snaplen: {size}")
    plt.ylabel("Memory (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot Memory")
    plt.savefig(f"../../img/{size}/memory.png")
    
    df.plot(x="Speed", y=["Drop Rate_suricata", "Drop Rate_snort3","Drop Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title(f"Drop Rate : Snaplen: {size}")
    plt.ylabel("Drop Rate (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot Drop Rate")
    plt.savefig(f"../../img/{size}/drop_rate.png")

    df.plot(x="Speed", y=["Packet Analysis Rate_suricata", "Packet Analysis Rate_snort3","Packet Analysis Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title(f"Packet Analysis Rate Snaplen: {size}")
    plt.ylabel("Packet Analysis Rate (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot Packet Analysis Rate")
    plt.savefig(f"../../img/{size}/packet_analysis_rate.png")


#visualize(512)