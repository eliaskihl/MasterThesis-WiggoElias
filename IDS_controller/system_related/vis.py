import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import os
import re
import argparse
import networkx as nx
import pickle
import seaborn as sns

def crashed_plot(throughput):
    with open(f"./zeekctl/perf_files/count_crashed_{str(throughput)}.txt", "rb") as file:
        crashes = eval(file.read())
    N = len(crashes.keys())
    df = pd.Series(np.random.randint(10,50,N), index=np.arange(1,N+1))

    cmap = plt.cm.tab10

    roles = list(crashes.keys())
    freq = list(crashes.values())
    data = pd.DataFrame(list(zip(roles,freq)),columns=["role","freq"])

    colors = cmap(np.arange(len(df)) % cmap.N)
    sns.set_style("whitegrid")
    sns.barplot(data,x="role",y="freq",palette='Set1')

    plt.xlabel('')
    plt.ylabel("Number of shutdowns")
    plt.title("Number of shutdowns per node")
    plt.savefig(f"../../img/controller/crashed_nodes_{str(throughput)}.png")

def latency_plot(throughput):
    
    with open(f"./zeekctl/perf_files/latencies_{str(throughput)}.txt", "rb") as file:
        latencies = eval(file.read())
    # Extract to dataframe
    # Flatten to single-row DataFrame
    df = pd.DataFrame()
    file = "./df_latency_between_nodes.csv"
    if os.path.exists(file):
            with open(file, "r") as f:
                df_tot = pd.read_csv(f)
    else:
        df_tot = pd.DataFrame()
    # Temporary dataframe
    df = pd.DataFrame()
    G = nx.MultiDiGraph()  # Supports directional and multiple edges

    # Build graph
    for (src, dst), latency in latencies.items():
        G.add_edge(src, dst, weight=latency)
        df[f"Latency_between_{src}_{dst}"] = [latency]
        print(src,dst,latency)
    print(df)
    # Append to total df
    pd.concat([df_tot,df])
    # Save df
    df_tot.to_csv(file)


    # Layout
    pos = nx.spring_layout(G, k=2, iterations=25, seed=42)

    plt.figure(figsize=(10, 7))
    plt.title(f"Node-to-Node Latency Map | Zeekctl | Throughput: {str(throughput)}")

    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_color='skyblue', node_size=800)
    nx.draw_networkx_labels(G, pos, font_size=10)

    # Draw curved edges with arrows
    nx.draw_networkx_edges(
        G, pos,
        edgelist=G.edges(keys=True),
        edge_color='gray',
        width=2,
        arrows=True,
        arrowsize=30
    )

    # Edge labels with better positioning
    edge_labels = {
        (u, v): f"{d['weight']*800:.2f} ms"
        for u, v, k, d in G.edges(keys=True, data=True)
    }

    # Automatically calculate positions for edge labels based on midpoints of the edges
    edge_label_pos = {}
    for (u, v) in edge_labels:
        x_pos = (pos[u][0] + pos[v][0]) / 2
        y_pos = (pos[u][1] + pos[v][1]) / 2
        edge_label_pos[(u, v)] = (x_pos, y_pos)

    # Draw edge labels with corrected positions (without redundant method)
    nx.draw_networkx_edge_labels(
        G, pos,
        edge_labels=edge_labels,
        font_size=8,
        font_color='black',
        bbox=dict(facecolor='white', edgecolor='none', boxstyle="round,pad=0.3"),
        font_weight='bold',
        horizontalalignment='center',
        verticalalignment='center'
    )

    plt.axis('off')
    plt.tight_layout()
    plt.savefig(f"../../img/controller/latency_network_{str(throughput)}.png")
    plt.close()


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
    plt.xlabel("Throughput (Mbps)")
    plt.legend()
    print("Saving plot Network")
    plt.savefig(f"../../img/controller/network.png")
    
def calc_mean(df,speed):
       
    
    avg_usage = df.groupby("Role").agg({"CPU_Usage": "mean", "Memory_Usage": "mean"}).reset_index()
    # Return a list of the "Roles"
    list_of_roles = avg_usage["Role"].to_list()
    # For each role get the drop rate
    
    list_of_drop_rates_values = []
    list_of_total_packets = []
    list_of_drop_rates_tcpreplay = []
    for role in list_of_roles:
        
        # drop_file = f"./zeekctl/perf_files/drop_rate_{role}_{speed}.txt"
        total_file = f"./zeekctl/perf_files/total_packets_{role}_{speed}.txt"
        tcp_drop_file = f"./zeekctl/perf_files/tcpreplay_drop_rate_{role}_{speed}.txt" 
        # if os.path.exists(drop_file):
        #     with open(drop_file, "r") as f:
        #         drop_rate = float(f.read())
        # else:
        #         drop_rate = 0.0

        # list_of_drop_rates_values.append(drop_rate)

        if os.path.exists(total_file):
            with open(total_file, "r") as f:
                total_packets = float(f.read())
        else:
            total_packets = 0

        list_of_total_packets.append(total_packets)

        if os.path.exists(tcp_drop_file):
            with open(tcp_drop_file, "r") as f:
                acc_drop_rate = float(f.read())
               
        else:
                acc_drop_rate = 0.0

        list_of_drop_rates_tcpreplay.append(acc_drop_rate)

    # avg_usage["Drop_Rate"] = list_of_drop_rates_values
    avg_usage["Drop_Rate"] = list_of_drop_rates_tcpreplay
    avg_usage["Total_Packets"] = list_of_total_packets
    print("list",list_of_roles)
    print("avg_usge:",avg_usage)
    return avg_usage,list_of_roles

def vis():
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
        
        df, list_of_roles = calc_mean(df,speed)
        
        # for speed value get latency and shutdown plots
        crashed_plot(speed)
        latency_plot(speed)
        

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
    exit(0)
    
    if not os.path.exists(f"../../img/controller/"):
        os.makedirs(f"../../img/controller")
    width,height = 8,6
    cpu_names=[]
    mem_names=[]
    drop_names=[]
    # acc_drop_names=[]
    total_names=[]
    for i in list_of_roles:
        cpu_names.append(f"{i}_CPU_Usage")
        mem_names.append(f"{i}_Memory_Usage")
        drop_names.append(f"{i}_Drop_Rate")
        # acc_drop_names.append(f"{i}_Actual_Drop_Rate")
        total_names.append(f"{i}_Total_Packets")

    # Save csv
    if not os.path.exists(f"../../tables/controller/"):
        os.makedirs(f"../../tables/controller/")
    final_df.to_csv(f"../../tables/controller/syseval.csv")
    print("saved")

    final_df.plot(x="Speeds", y=cpu_names, kind="bar", figsize=(width,height), label=list_of_roles)
    plt.title(f"CPU Usage Zeekctl")
    plt.ylabel("CPU (%)")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot CPU")
    plt.savefig(f"../../img/controller/cpu.png")
    plt.clf()  # Clear the figure

    final_df.plot(x="Speeds", y=mem_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Memory Usage Zeekctl")
    plt.ylabel("Memory (%)")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot Memory")
    plt.savefig(f"../../img/controller/memory.png")
    plt.clf()  # Clear the figure

    final_df.plot(x="Speeds", y=drop_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Drop Rate Zeekctl")
    plt.ylabel("Drop Rate (%)")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot Drop Rate")
    plt.savefig(f"../../img/controller/drop_rate.png")
    plt.clf()  # Clear the figure

    # final_df.plot(x="Speeds", y=acc_drop_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    # plt.title(f"Actual Drop Rate Zeekctl")
    # plt.ylabel("Drop Rate (%)")
    # plt.xlabel("Throughput (Mbps)")
    # print("Saving plot Actual Drop Rate")
    # plt.savefig(f"../../img/controller/actual_drop_rate.png")
    # plt.clf()  # Clear the figure

    final_df.plot(x="Speeds", y=total_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Total Packets Zeekctl")
    plt.ylabel("Number of packets")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot Total Packets")
    plt.savefig(f"../../img/controller/total_packets.png")
    plt.clf()  # Clear the figure
    # plt.savefig(f"../.../../img/{folder}/total_packets_sent.png")
    # Network plot
    #network_plot(network_dict)

    


def visualize_controller():
    vis()


