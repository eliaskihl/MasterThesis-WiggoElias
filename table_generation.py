# Unite all dfs
import pandas as pd
import argparse
import os
import subprocess

def table_generation(run_all=False):
    
    if run_all:
        commands = [
            ["python", "run.py", "-tool", "datasets_traffic_generators"],
            ["python", "run.py", "-tool", "visualize", "-type", "regular"],
            
            ["python", "run.py", "-tool", "visualize", "-type", "latency"],
            ["python", "run.py", "-tool", "visualize_controller"]
        ]

        for cmd in commands:
            try:
                print(f"\nRunning command: {' '.join(cmd)}")
                result = subprocess.run(cmd, check=True)
                print("Finished successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Command failed with return code {e.returncode}")
                break  # Optional: Stop on first failure
            except Exception as e:
                print(f"Unexpected error: {e}")
                break

    latency_df = pd.read_csv("./tables/latency/syseval.csv")
    regular_df = pd.read_csv("./tables/regular/syseval.csv")
    controller_df = pd.read_csv("./tables/controller/syseval.csv")
    datasets_df = pd.read_csv("./tables/classification_evaluation/classifications.csv")
    
    
    datasets_df["Dataset/Traffic_Gen"] = datasets_df["dataset"].fillna('') + "" + datasets_df["traffic_generator"].fillna('')
    datasets_df["Pcap/Attack"] = datasets_df["pcap"].fillna('') + "" + datasets_df["attack"].fillna('')
    
    
    datasets_df = datasets_df.drop(columns=["dataset", "traffic_generator", "pcap", "attack"])
    
    # datasets_df.to_csv("./tables/dataset_classification/Test/Dataset/Traffic Generator2.csv")
    
    zeek_df = datasets_df[datasets_df['tool'] == 'zeek'].copy()
    snort_df = datasets_df[datasets_df['tool'] == 'snort'].copy()
    suricata_df = datasets_df[datasets_df['tool'] == 'suricata'].copy()
    print("1",datasets_df)
    # Rename columns for each tool
    zeek_df = zeek_df.rename(columns=lambda x: f"zeek_{x}" if x not in ['Dataset/Traffic_Gen', 'Pcap/Attack'] else x)
    snort_df = snort_df.rename(columns=lambda x: f"snort_{x}" if x not in ['Dataset/Traffic_Gen', 'Pcap/Attack'] else x)
    suricata_df = suricata_df.rename(columns=lambda x: f"suricata_{x}" if x not in ['Dataset/Traffic_Gen', 'Pcap/Attack'] else x)
    # Merge on dataset + attack
    print("2",datasets_df)
    new_datasets_df = pd.merge(zeek_df, snort_df, on=["Dataset/Traffic_Gen", "Pcap/Attack"], how="outer")
    new_datasets_df = pd.merge(new_datasets_df, suricata_df, on=["Dataset/Traffic_Gen", "Pcap/Attack"], how="outer")
    new_datasets_df = new_datasets_df.drop(columns=[col for col in new_datasets_df.columns if "tool" in col])
    # Reorder
    cols = new_datasets_df.columns.tolist()
    new_order = ['Dataset/Traffic_Gen', 'Pcap/Attack'] + [col for col in cols if col not in ['Dataset/Traffic_Gen', 'Pcap/Attack']]

    new_datasets_df = new_datasets_df[new_order]
    print("3",new_datasets_df)
    

    # Remove "unnamed" column
    latency_df = latency_df.loc[:, ~latency_df.columns.str.contains('^Unnamed')]
    regular_df = regular_df.loc[:, ~regular_df.columns.str.contains('^Unnamed')]
    controller_df = controller_df.loc[:, ~controller_df.columns.str.contains('^Unnamed')]
    new_datasets_df = new_datasets_df.loc[:, ~new_datasets_df.columns.str.contains('^Unnamed')]
   
    regular_df["Test/Dataset/Traffic Generator"] = "Throughput"
    latency_df["Test/Dataset/Traffic Generator"] = "Latency"
    controller_df["Test/Dataset/Traffic Generator"] = "Throughput"
    


    regular_df['Throughput'] = regular_df['Throughput'].apply(lambda x: f"{int(x)}")
    latency_df['Latency'] = latency_df['Latency'].apply(lambda x: f"{int(x)}")
    controller_df['Throughput'] = controller_df['Throughput'].apply(lambda x: f"{int(x)}")

    

    regular_df = regular_df.rename(columns={'Throughput': 'Value/Pcap/Attack'})
    latency_df = latency_df.rename(columns={'Latency': 'Value/Pcap/Attack'})
    controller_df = controller_df.rename(columns={'Throughput': 'Value/Pcap/Attack'})
    new_datasets_df = new_datasets_df.rename(columns={'Dataset/Traffic_Gen': 'Test/Dataset/Traffic Generator', 'Pcap/Attack': 'Value/Pcap/Attack'})
    print("4",new_datasets_df)

    
    """ To merge Controller and Regular they need to have the same recorded throughputs in row_value."""
    # df_merged = regular_df.merge(controller_df, on='row_value')
    # print(df_merged)
    # exit(0)
    # Concatenate vertically (stack)
    combined_df = pd.concat([regular_df, latency_df,controller_df,new_datasets_df]) #,controller_df
    # New order
    cols = combined_df.columns.tolist()
    new_order = ['Test/Dataset/Traffic Generator', 'Value/Pcap/Attack'] + [col for col in cols if col not in ['Test/Dataset/Traffic Generator', 'Value/Pcap/Attack']]
    combined_df = combined_df[new_order]
    print("-----------fin------------")
    print(combined_df)
    

    combined_df.to_csv("./tables/all_metrics.csv")
    
