import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import os
import re

def calc_mean(ids_performance_log,speed):
    df = pd.read_csv(ids_performance_log)    
    
    avg_usage = df.groupby("Role").agg({"CPU_Usage": "mean", "Memory_Usage": "mean"}).reset_index()
    # Return a list of the "Roles"
    list_of_roles = avg_usage["Role"].to_list()
    # For each role get the drop rate
    
    list_of_drop_rates_values = []
    list_of_total_packets = []
    for role in list_of_roles:
        
        
        drop_file = f"./zeekctl/perf_files/drop_rate_{role}_{speed}.txt"
        total_file = f"./zeekctl/perf_files/total_packets_{role}_{speed}.txt"
        if os.path.exists(drop_file):
            with open(drop_file, "r") as f:
                drop_rate = float(f.read())
        else:
                drop_rate = 0.0

        list_of_drop_rates_values.append(drop_rate)

        if os.path.exists(total_file):
            with open(total_file, "r") as f:
                total_packets = float(f.read())
        else:
            total_packets = 0

        list_of_total_packets.append(total_packets)
    avg_usage["Drop_Rate"] = list_of_drop_rates_values
    avg_usage["Total_Packets"] = list_of_total_packets
    print("list",list_of_roles)
    print("avg_usge:",avg_usage)
    return avg_usage,list_of_roles

def visualize():
    speeds = []

    print("Current Working Directory:", os.getcwd())
    final_df = pd.DataFrame()
    files = glob.glob(f"./zeekctl/perf_files/ids_performance_log*.csv")
    files = sorted(files, key=lambda x: int(re.search(r'(\d+)', x).group()))
    print(files)
    for idx,file in enumerate(files):
        speeds = []
        print("File", file)
        
        
        speed = (int(file.split("_")[-1].split(".")[0]))
        df, list_of_roles = calc_mean(file,speed)
        print("len:",len(list_of_roles))
        for i in range(len(list_of_roles)):
            speeds.append(speed)
        print(speeds)
        
        df["Speeds"] = speeds
        
        print("first_Df:",df)
        
        pivot_df = df.pivot_table(index="Speeds", columns="Role", values=["CPU_Usage", "Memory_Usage", "Drop_Rate","Total_Packets"])
        pivot_df.columns = [f"{col[1]}_{col[0]}" for col in pivot_df.columns] # Keep the CPU and Memory labels in the column names
        pivot_df.reset_index(inplace=True)
        print("pivot:",pivot_df)
        

               
        # Merge with the final_df
        if final_df.empty:
            final_df = pivot_df
        else:
            final_df = pd.concat([final_df, pivot_df], axis=0, ignore_index=True)
        
        # drop_rate_logger-1_10.txt
        # When idx == 0 create columns:
        number_of_speeds = len(files)-1
       

        # Clear lists
    speeds = []     
  
    print("Final:\n",final_df)
    
        
    
    
    if not os.path.exists(f"./img/controller/"):
        os.makedirs(f"./img/controller")
    width,height = 8,6
    cpu_names=[]
    mem_names=[]
    drop_names=[]
    total_names=[]
    for i in list_of_roles:
        cpu_names.append(f"{i}_CPU_Usage")
        mem_names.append(f"{i}_Memory_Usage")
        drop_names.append(f"{i}_Drop_Rate")
        total_names.append(f"{i}_Total_Packets")

    final_df.plot(x="Speeds", y=cpu_names, kind="bar", figsize=(width,height), label=list_of_roles)
    plt.title(f"CPU Usage Zeekctl")
    plt.ylabel("CPU (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot CPU")
    plt.savefig(f"./img/controller/cpu.png")
    
    final_df.plot(x="Speeds", y=mem_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Memory Usage Zeekctl")
    plt.ylabel("Memory (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot Memory")
    plt.savefig(f"./img/controller/memory.png")
    
    final_df.plot(x="Speeds", y=drop_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Drop Rate Zeekctl")
    plt.ylabel("Drop Rate (%)")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot Drop Rate")
    plt.savefig(f"./img/controller/drop_rate.png")

    final_df.plot(x="Speeds", y=total_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Total Packets Zeekctl")
    plt.ylabel("Number of packets")
    plt.xlabel("Speed (mbit/s)")
    print("Saving plot Total Packets")
    plt.savefig(f"./img/controller/total_packets.png")


visualize()