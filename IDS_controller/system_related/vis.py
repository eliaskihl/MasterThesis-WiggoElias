import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import os
import re

def extract_network_usage(df):
    # Extract the two column with network upload and download speed
    # Get the average of each run
    # return a dict with speed and tuple (download,upload)
    #df = df.drop(df.columns.difference(["Upload_Speed",'Download_Speed']), 1, inplace=True)
    avg_upload_speed = df["Upload_Speed"].mean()
    avg_download_speed = df["Download_Speed"].mean()
    print(type(avg_download_speed))
    return avg_download_speed,avg_upload_speed

def network_plot(data_dict):
    # colors = plt.cm.Paired(np.linspace(0,1,len(states)))
    # patches = []
    # for state,c in zip(states,colors):
    #     plt.fill_between(years, data[state], color=c, alpha=0.5)
    #     patches.append(mpatches.Patch(color=c, label=state))
    # plt.legend(handles=patches, loc=”upper left”)
    # plt.xlabel(”Year”)
    # plt.ylabel(”No. Students Taking CS AP Exam”)
    # plt.title(”No. Students Taking CS AP Exam by Year”)
    # plt.savefig(”out2.png”)
    speeds = list(data_dict.keys())
    uploads = [val[1] for val in data_dict.values()]
    downloads = [val[0] for val in data_dict.values()]
    print("speeds:",speeds)
    print("uploads",uploads)
    print("downloasd",downloads)
    plt.plot(speeds,uploads, label="Upload Speed")
    plt.plot(speeds,downloads,label="Download Speed")
    plt.title("Network Usage")
    plt.ylabel("Network Speed (KB/s)")
    plt.xlabel("Throughput (mbit/s)")
    plt.legend()
    print("Saving plot Network")
    plt.savefig(f"./img/controller/network.png")
    
def calc_mean(df,speed):
       
    
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
    network_dict = {}
    print("Current Working Directory:", os.getcwd())
    final_df = pd.DataFrame()
    files = glob.glob(f"./zeekctl/perf_files/ids_performance_log*.csv")
    files = sorted(files, key=lambda x: int(re.search(r'(\d+)', x).group()))
    print(files)
    for file in files:
        speeds = []
        print("File", file)
        
        
        speed = (int(file.split("_")[-1].split(".")[0]))
        df = pd.read_csv(file)
        download_speed,upload_speed = extract_network_usage(df) 
        network_dict[speed] = (download_speed,upload_speed)
        df, list_of_roles = calc_mean(df,speed)
        
        for i in range(len(list_of_roles)):
            speeds.append(speed)
        print(speeds)
        
        df["Speeds"] = speeds
        
        print("first_Df:",df)
        
        pivot_df = df.pivot_table(index="Speeds", columns="Role", values=["CPU_Usage", "Memory_Usage", "Drop_Rate", "Total_Packets"])
        pivot_df.columns = [f"{col[1]}_{col[0]}" for col in pivot_df.columns] # Keep the CPU and Memory labels in the column names
        pivot_df.reset_index(inplace=True)
        print("pivot:",pivot_df)
    
        # Merge with the final_df
        if final_df.empty:
            final_df = pivot_df
        else:
            final_df = pd.concat([final_df, pivot_df], axis=0, ignore_index=True)
        
       
    # Clear list
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
    plt.xlabel("Throughput (mbit/s)")
    print("Saving plot CPU")
    plt.savefig(f"./img/controller/cpu.png")
    plt.clf()  # Clear the figure

    final_df.plot(x="Speeds", y=mem_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Memory Usage Zeekctl")
    plt.ylabel("Memory (%)")
    plt.xlabel("Throughput (mbit/s)")
    print("Saving plot Memory")
    plt.savefig(f"./img/controller/memory.png")
    plt.clf()  # Clear the figure

    final_df.plot(x="Speeds", y=drop_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Drop Rate Zeekctl")
    plt.ylabel("Drop Rate (%)")
    plt.xlabel("Throughput (mbit/s)")
    print("Saving plot Drop Rate")
    plt.savefig(f"./img/controller/drop_rate.png")
    plt.clf()  # Clear the figure

    final_df.plot(x="Speeds", y=total_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Total Packets Zeekctl")
    plt.ylabel("Number of packets")
    plt.xlabel("Throughput (mbit/s)")
    print("Saving plot Total Packets")
    plt.savefig(f"./img/controller/total_packets.png")
    plt.clf()  # Clear the figure

    # Network plot
    network_plot(network_dict)
    

    




visualize()