import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import os

def calc_mean(ids_performance_log):
    df = pd.read_csv(ids_performance_log)    
    # filter out rows that have cpu_usage between 0.0 and 2.0
    df = df[df["CPU_Usage"] > 2.0]
    avg_usage = df.groupby("Role").agg({"CPU_Usage": "mean", "Memory_Usage": "mean"}).reset_index()
    print(avg_usage)
    return avg_usage

def visualize():
    speeds = []
    
    # Create empty dataframe
    list_of_roles = []
    print("Current Working Directory:", os.getcwd())
    final_df = pd.DataFrame()
    files = glob.glob(f"./zeekctl/perf_files/ids_performance_log*.csv")
    for file in files:
        
        print("File", file)
        speed = (int(file.split("_")[-1].split(".")[0]))
        avg_usage = calc_mean(file)
        for i in range(avg_usage.shape[0]):
            speeds.append(speed)
        df_speed = pd.DataFrame({'Speeds':speeds})
        
        
        df = pd.concat([avg_usage,df_speed], axis=1)
        print(df)
        for i in df["Role"]:
            list_of_roles.append(i) 
        pivot_df = df.pivot_table(index="Speeds", columns="Role", values=["CPU_Usage", "Memory_Usage"])
        pivot_df.columns = [f"{col[1]}_{col[0]}" for col in pivot_df.columns] # Keep the CPU and Memory labels in the column names
        pivot_df.reset_index(inplace=True)
        # Merge with the final_df
        if final_df.empty:
            final_df = pivot_df
        else:
            final_df = pd.concat([final_df, pivot_df], axis=0, ignore_index=True)
        print(final_df)
        speeds = []
        
  
    print("Final:\n",final_df)

        
    
    
    if not os.path.exists(f"./img/controller/"):
        os.makedirs(f"./img/controller")
    width,height = 8,6
    cpus=[]
    for i in list_of_roles:
        cpus.append(f"{i}_CPU_Usage")

    final_df.plot(x="Speeds", y=cpus, kind="bar", figsize=(width,height), label=list_of_roles)
    plt.title(f"CPU Usage Zeekctl")
    plt.ylabel("CPU (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot CPU")
    plt.savefig(f"./img/controller/cpu.png")
    
    # df.plot(x="Speed", y=["Memory_suricata", "Memory_snort3","Memory_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    # plt.title(f"Memory Usage : Snaplen: controller")
    # plt.ylabel("Memory (%)")
    # plt.xlabel("Speed (mbit/s)")
    # print("Saving plot Memory")
    # plt.savefig(f"../../img/controller/memory.png")
    
    # df.plot(x="Speed", y=["Drop Rate_suricata", "Drop Rate_snort3","Drop Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    # plt.title(f"Drop Rate : Snaplen: controller")
    # plt.ylabel("Drop Rate (%)")
    # plt.xlabel("Speed (mbit/s)")
    # print("Saving plot Drop Rate")
    # plt.savefig(f"../../img/controller/drop_rate.png")

    # df.plot(x="Speed", y=["Packet Analysis Rate_suricata", "Packet Analysis Rate_snort3","Packet Analysis Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    # plt.title(f"Packet Analysis Rate Snaplen: controller")
    # plt.ylabel("Packet Analysis Rate")
    # plt.xlabel("Speed (mbit/s)")
    # print("Saving plot Packet Analysis Rate")
    # plt.savefig(f"../../img/controller/packet_analysis_rate.png")


visualize()