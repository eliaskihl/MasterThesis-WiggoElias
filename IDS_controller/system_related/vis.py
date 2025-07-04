import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import glob
import os
import re
import networkx as nx

def crashed_plot(throughput):
    with open(f"./zeekctl/perf_files/count_crashed_{str(throughput)}.txt", "rb") as file:
        crashes = eval(file.read())

    if crashes == None:
        print(f"There are no values recorded in file: latencies_{str(throughput)}.txt")

    df = pd.DataFrame()
    file = "./node_shutdowns.csv"
    if os.path.exists(file) and os.path.getsize(file) > 0:
            with open(file, "r") as f:
                df_tot = pd.read_csv(f)
    else:
        df_tot = pd.DataFrame()
   
    row = {"Throughput": throughput}

    for rol,freq in crashes.items():
        col_name = f"Shutdowns_for_{rol}"
        row[col_name] = freq

    df = pd.DataFrame([row])
        
    
    # Append to total df
    df_tot = pd.concat([df_tot,df])
    # Save df
    df_tot.to_csv(file,index=False)





def latency_plot(throughput):
    latencies = {}
    with open(f"./zeekctl/perf_files/latencies_{str(throughput)}.txt", "rb") as file:
        latencies = eval(file.read())
    
    if latencies == None:
        print(f"There are no values recorded in file: latencies_{str(throughput)}.txt")
   
    # Extract to dataframe
    # Flatten to single-row DataFrame
    df = pd.DataFrame()
    file = "./df_latency_between_nodes.csv"
    if os.path.exists(file) and os.path.getsize(file) > 0:
            with open(file, "r") as f:
                df_tot = pd.read_csv(f)
    else:
        df_tot = pd.DataFrame()
    # Temporary dataframe
    df = pd.DataFrame()
    G = nx.MultiDiGraph()  # Supports directional and multiple edges
    row = {"Throughput": throughput}

    # Build graph
    for (src, dst), latency in latencies.items():
        G.add_edge(src, dst, weight=latency)
        
        lat = 1000*latency
        if lat < 1000:
            col_name = f"Latency(ms)_{src}_{dst}"
            row[col_name] = lat # from s to ms
         # Check if any latencies are obscure > 1000
    
        
        # print(src, dst, latency)
        
   
    #print(src, dst, latency)

    df = pd.DataFrame([row])
        
    #print(df)
    # Append to total df
    df_tot = pd.concat([df_tot,df])
    # Save df
    df_tot.to_csv(file,index=False)


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
    return avg_download_speed,avg_upload_speed

def network_plot(data_dict):
    
    speeds = list(data_dict.keys())
    uploads = [val[1] for val in data_dict.values()]
    downloads = [val[0] for val in data_dict.values()]
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
    list_of_total_packets = []
    list_of_drop_rates_tcpreplay = []
    for role in list_of_roles:
        
        total_file = f"./zeekctl/perf_files/total_packets_{role}_{speed}.txt"
        tcp_drop_file = f"./zeekctl/perf_files/tcpreplay_drop_rate_{role}_{speed}.txt" 
        
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

    avg_usage["Drop_Rate"] = list_of_drop_rates_tcpreplay
    avg_usage["Total_Packets"] = list_of_total_packets
    
    return avg_usage,list_of_roles

def vis():
    speeds = []
    
    final_df = pd.DataFrame()
    files = glob.glob(f"./zeekctl/perf_files/ids_performance_log*.csv")
    files = sorted(files, key=lambda x: int(re.search(r'(\d+)', x).group()))
    print(files)
    for file in files:
        speeds = []
        
        
        
        speed = (int(file.split("_")[-1].split(".")[0]))
        df = pd.read_csv(file)
        
        df, list_of_roles = calc_mean(df,speed)
        
        # For speed value get latency and shutdown plots
        crashed_plot(speed)
        latency_plot(speed)
        

        for i in range(len(list_of_roles)):
            speeds.append(speed)
        
        
        df["Throughput"] = speeds
        
        
        
        pivot_df = df.pivot_table(index="Throughput", columns="Role", values=["CPU_Usage", "Memory_Usage", "Drop_Rate", "Total_Packets"])
        pivot_df.columns = [f"{col[1]}_{col[0]}" for col in pivot_df.columns] # Keep the CPU and Memory labels in the column names
        pivot_df.reset_index(inplace=True)
        
    
        # Merge with the final_df
        if final_df.empty:
            final_df = pivot_df
        else:
            final_df = pd.concat([final_df, pivot_df], axis=0, ignore_index=True)
        
       
    # Clear list
    speeds = []     
    print("Final:\n",final_df)
    
    
    list_of_roles = [role for role in list_of_roles if role != "Unknown"]
    
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

    # Save csv
    if not os.path.exists(f"../../tables/controller/"):
        os.makedirs(f"../../tables/controller/")

    # Append latency and shutdown dfs
    latency_df = pd.read_csv("./df_latency_between_nodes.csv")
    shutdown_df = pd.read_csv("./node_shutdowns.csv")
    final_df = pd.merge(final_df, latency_df, on='Throughput', how='inner') 
    final_df = pd.merge(final_df, shutdown_df, on='Throughput', how='inner')
    # Clean Unknown role
    final_df = final_df.loc[:, ~final_df.columns.str.contains('Unknown')]
    final_df.to_csv(f"../../tables/controller/syseval.csv")
    
    print("Final2:\n",final_df)

    final_df.plot(x="Throughput", y=cpu_names, kind="bar", figsize=(width,height), label=list_of_roles)
    plt.title(f"CPU Usage Zeekctl")
    plt.ylabel("CPU (%)")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot CPU")
    plt.savefig(f"../../img/controller/cpu.png")
    plt.clf()  # Clear the figure

    final_df.plot(x="Throughput", y=mem_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Memory Usage Zeekctl")
    plt.ylabel("Memory (%)")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot Memory")
    plt.savefig(f"../../img/controller/memory.png")
    plt.clf()  # Clear the figure

    final_df.plot(x="Throughput", y=drop_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Drop Rate Zeekctl")
    plt.ylabel("Drop Rate (%)")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot Drop Rate")
    plt.savefig(f"../../img/controller/drop_rate.png")
    plt.clf()  # Clear the figure

    

    final_df.plot(x="Throughput", y=total_names, kind="bar", figsize=(width,height),  label=list_of_roles)
    plt.title(f"Total Packets Zeekctl")
    plt.ylabel("Number of packets")
    plt.xlabel("Throughput (Mbps)")
    print("Saving plot Total Packets")
    plt.savefig(f"../../img/controller/total_packets.png")
    plt.clf()  # Clear the figure
    
    # Shutdown
    df = pd.read_csv("./node_shutdowns.csv")
    roles = df.columns[1:]  # all roles (excluding Throughput)

    for role in roles:
        plt.plot(df['Throughput'], df[role], marker='o', label=role.replace('Shutdowns_for_', ''))

    plt.xlabel('Throughput')
    plt.ylabel('Frequency of Shutdowns')
    plt.title('Shutdown Frequency per Role vs Throughput')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"../../img/controller/nodes_shutdowns.png")
    plt.clf()  # Clear the figure

    # Latencies Overview
    # Do for each role 
    
    # Load data
    df = pd.read_csv("./df_latency_between_nodes.csv")

    # Extract all latency columns
    latency_cols = [col for col in df.columns if col.startswith('Latency(ms)_')]

    # Get unique source roles (e.g., 'logger-1', 'manager', etc.)
    source_roles = set(col.split('_')[1] for col in latency_cols)

    # Plot for each source role
    for role1 in source_roles:
        # Find columns where this role is the source
        role_cols = [col for col in latency_cols if col.startswith(f'Latency(ms)_{role1}_')]
        if not role_cols:
            continue

        # Clean labels: extract only the target part
        cleaned_labels = [col.split(f'Latency(ms)_{role1}_')[1] for col in role_cols]

        plt.figure(figsize=(10, 6))
        for col, label in zip(role_cols, cleaned_labels):
            plt.plot(df['Throughput'], df[col], marker='o', label=label)

        print(f"Saving latency plot for {role1}")
        plt.xlabel('Throughput')
        plt.ylabel('Latency (ms)')
        plt.title(f'Latencies from {role1} (max is 1000)')
        plt.legend(title='Target')
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(f"../../img/controller/latency_overview_{role1}.png")
        plt.clf()


def visualize_controller():
    if not os.path.exists(f"../../img/controller/"):
        os.makedirs(f"../../img/controller")
    # Clean latency file before start
    file = "./df_latency_between_nodes.csv"
    open(file, "w").close()
    # Clean num of shutdowns file before start
    file = "./node_shutdowns.csv"
    open(file, "w").close()    

    vis()


