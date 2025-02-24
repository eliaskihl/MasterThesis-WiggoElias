import subprocess
import argparse
import os
import glob
import pandas as pd
import numpy as np
import json
from datetime import datetime
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

def run_suricata(pcap_file):
    """Run Suricata on the provided PCAP file."""
    cmd = ["sudo", "suricata", "-r", pcap_file, "-l", "./logs", "-v"]
    subprocess.run(cmd, check=True)

def run_dataset():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Run Suricata on specified PCAP dataset.")
    
    # Add an argument for the dataset
    parser.add_argument(
        "dataset", 
        choices=[
            "TII-SSRC-23", 
            "UNSW-NB15" 
        ], 
        help="Choose a dataset to run Suricata on"
    )
    
    # Parse the arguments
    args = parser.parse_args()

    # Based on the dataset argument, select the correct PCAP file path
    dataset_paths = {
        "TII-SSRC-23": "../datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_http.pcap",
        "UNSW-NB15": "../datasets/UNSW-NB15/pcap/file_name.pcap"  # Provide the correct path for UNSW-NB15 PCAP
    }
    
    # Call run_suricata with the selected PCAP file
    pcap_file = dataset_paths[args.dataset]
    run_suricata(pcap_file)
    
    return args.dataset  # Return selected dataset name to be used in the log processing

def process_logs(dataset):
    """Process the Suricata logs based on the selected dataset."""
    if dataset == "UNSW-NB15":
        process_unsw_nb15_logs()
    elif dataset == "TII-SSRC-23":

        process_tii_ssrc_23_logs()
    else:
        print(f"No processing logic available for the dataset: {dataset}")

def process_unsw_nb15_logs():
    """Process the UNSW-NB15 dataset logs."""
    def progress_bar(current, total):
        print()
        print('[', end='')
        for i in range(total):
            if i < current:
                print('=', end='')
            else:
                print(' ', end='')
        print(']', end='')
        print()
    
    def init_gt():
        df_gt = pd.read_csv('./datasets/UNSW-NB15/gt/UNSW-NB15_1.csv')
        df_col = pd.read_csv('./datasets/UNSW-NB15/gt/NUSW-NB15_features.csv', encoding='ISO-8859-1')
        df_col['Name'] = df_col['Name'].apply(lambda x: x.strip().replace(' ', '').lower())
        df_gt.columns = df_col['Name']
        column_mapping = {
            "srcip": "src_ip",
            "sport": "src_port",
            "dstip": "dest_ip",
            "dsport": "dest_port",
            "stime" : "timestamp",
            "state": "flow.state",
            "service": "app_proto",
            "sbytes": "flow.bytes_toserver",
            "dbytes": "flow.bytes_toclient",
            "timestamp" : "flow.time",
            "service" : "app_proto",
        }
        df_gt.rename(columns=column_mapping, inplace=True)
        df_gt = df_gt[['src_ip', 'dest_ip','src_port','dest_port', 'proto','label']]
        df_gt.dropna(inplace=True)
        df_gt['proto'] = df_gt['proto'].str.lower()
        df_gt["src_port"] = pd.to_numeric(df_gt["src_port"], errors="coerce")
        df_gt["dest_port"] = pd.to_numeric(df_gt["dest_port"], errors="coerce")
        df_gt = df_gt.dropna(subset=["src_port", "dest_port"])
        df_gt['label'] = df_gt['label'].replace(0, False)
        df_gt['label'] = df_gt['label'].replace(1, True)
        df_gt = df_gt[df_gt['src_ip'].str.contains(r'^\d', na=False)]
        df_gt = df_gt[df_gt['dest_ip'].str.contains(r'^\d', na=False)]
        df_gt['src_port'] = df_gt['src_port'].astype(int)
        df_gt['dest_port'] = df_gt['dest_port'].astype(int)
        return df_gt
    
    def json_to_csv(file_path):
        chunk_size = 10000  # Number of rows per chunk
        dfs = []
        for chunk in pd.read_json(file_path, lines=True, chunksize=chunk_size):
            dfs.append(chunk[["src_ip", "dest_ip","src_port","dest_port","proto", "event_type"]])
        df_sur = pd.concat(dfs, ignore_index=True)
        return df_sur
    
    files = glob.glob("./datasets/UNSW-NB15/eve_files/*/eve.json")
    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0
    df_gt = init_gt()
    
    for file_path in files:
        df_sur = json_to_csv(file_path)
        if 'flow.start' in df_sur.columns and 'flow.end' in df_sur.columns:
            df_sur['flow.start'] = pd.to_datetime(df_sur['flow.start'])
            df_sur['flow.end'] = pd.to_datetime(df_sur['flow.end'])
            df_sur['dur'] = df_sur['flow.end'] - df_sur['flow.start']

        df_sur = df_sur[['src_ip', 'dest_ip','src_port','dest_port', 'proto','event_type']]
        df_sur.dropna(inplace=True)
        df_sur['proto'] = df_sur['proto'].str.lower()
        df_sur = df_sur[df_sur['src_ip'].str.contains(r'^\d', na=False)]
        df_sur = df_sur[df_sur['dest_ip'].str.contains(r'^\d', na=False)]
        df_sur['src_port'] = df_sur['src_port'].astype(int)
        df_sur['dest_port'] = df_sur['dest_port'].astype(int)
        df_merged = pd.merge(df_sur, df_gt, on=['src_ip', 'dest_ip','src_port','dest_port', 'proto'], how='inner', suffixes=('_suricata', '_gt'))
        df_merged.dropna(inplace=True)
        df_true_negative = df_merged[(df_merged["event_type"] != "alert") & (df_merged["label"] == False)]
        df_false_negatives = df_merged[(df_merged["event_type"] != "alert") & (df_merged["label"] == True)]
        df_alerts = df_merged[df_merged['event_type'] == "alert"]
        df_merged = pd.concat([df_false_negatives, df_alerts], ignore_index=True)
        true_pos = df_merged[(df_merged["event_type"] == "alert") & (df_merged["label"] == True)]
        false_pos = df_merged[(df_merged["event_type"] == "alert") & (df_merged["label"] == False)]
        
        print(f"File name: {file_path}")
        print(f"Alerts: {len(df_alerts)}")
        print(f"True positives: {len(true_pos)}")
        print(f"False positives: {len(false_pos)}")
        print(f"True negatives: {len(df_true_negative)}")
        print(f"False negatives: {len(df_false_negatives)}")
        
        tot_true_pos += len(true_pos)
        tot_false_pos += len(false_pos)
        tot_false_neg += len(df_false_negatives)
        tot_true_neg += len(df_true_negative)
        progress_bar(files.index(file_path)+1, len(files))
    
    print("=====================================")
    print(f"Total True positives: {tot_true_pos}")
    print(f"Total False positives: {tot_false_pos}")
    print(f"Total False negatives: {tot_false_neg}")
    print(f"Total True negatives: {tot_true_neg}")

    accuracy = (tot_true_pos + tot_true_neg) / (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) if (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) != 0 else 0
    recall = tot_true_pos / (tot_true_pos + tot_false_neg) if (tot_true_pos + tot_false_neg) != 0 else 0
    precision = tot_true_pos / (tot_true_pos + tot_false_pos) if (tot_true_pos + tot_false_pos) != 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if precision + recall != 0 else 0

    print(f"Accuracy: {accuracy}")
    print(f"Recall: {recall}")
    print(f"Precision: {precision}")
    print(f"F1 score: {f1}")

def process_tii_ssrc_23_logs():

    df_gt = pd.read_csv('../datasets/TII-SSRC-23/ground_truth/Bruteforce HTTP.csv')

    column_mapping = {
    "Src IP": "src_ip",
    "Src Port": "src_port",
    "Dst IP": "dest_ip",
    "Dst Port": "dest_port",
    "Timestamp" : "timestamp",
    "Protocol": "proto",
    "Label": "flow_alerted",
    }

    df_gt.rename(columns=column_mapping, inplace=True)


    df_gt = df_gt[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'timestamp', 'proto', 'flow_alerted']]  # Keep only necessary columns

    # Replace values
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({'Benign': False, 'Malicious': True})
    df_gt['proto'] = df_gt['proto'].replace({6.0: 'TCP', 17.0: 'UDP', 0.0: 'HOPOPT'})



    df_suricata = pd.read_json('./logs/eve.json', lines=True)
    df_suricata = df_suricata[df_suricata['event_type'] == 'flow']
    df_suricata["flow_alerted"] = df_suricata["flow"].apply(lambda x: x.get("alerted", False) if isinstance(x, dict) else False)

    df_suricata = df_suricata[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'timestamp', 'proto', 'flow_alerted']]  # Keep only necessary columns
    


    df_merged = pd.merge(df_gt, df_suricata, how='inner', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'])
    df_merged = df_merged.drop_duplicates(subset=['src_port'], keep='first')

    df_merged.to_csv('df_merged',index=False)
    df_tp = df_merged[(df_merged["flow_alerted_x"] == True) & (df_merged["flow_alerted_y"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_x"] == False) & (df_merged["flow_alerted_y"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_x"] == False) & (df_merged["flow_alerted_y"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_x"] == True) & (df_merged["flow_alerted_y"] == False)]
    
    print(f"True positives: {len(df_tp)}")
    print(f"False positives: {len(df_fp)}")
    print(f"True negatives: {len(df_tn)}")
    print(f"False negatives: {len(df_fn)}")

    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0


    tot_true_pos += len(df_tp)
    tot_false_pos += len(df_fp)
    tot_false_neg += len(df_fn)
    tot_true_neg += len(df_tn)
    
    print("=====================================")
    print(f"Total True positives: {tot_true_pos}")
    print(f"Total False positives: {tot_false_pos}")
    print(f"Total False negatives: {tot_false_neg}")
    print(f"Total True negatives: {tot_true_neg}")

    accuracy = (tot_true_pos + tot_true_neg) / (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) if (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) != 0 else 0
    recall = tot_true_pos / (tot_true_pos + tot_false_neg) if (tot_true_pos + tot_false_neg) != 0 else 0
    precision = tot_true_pos / (tot_true_pos + tot_false_pos) if (tot_true_pos + tot_false_pos) != 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if precision + recall != 0 else 0

    print(f"Accuracy: {accuracy}")
    print(f"Recall: {recall}")
    print(f"Precision: {precision}")
    print(f"F1 score: {f1}")




if __name__ == "__main__":
    dataset = run_dataset()
    process_logs(dataset)
