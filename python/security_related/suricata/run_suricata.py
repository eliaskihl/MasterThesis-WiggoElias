import subprocess
import argparse
import os
import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from TII_SSRC_23 import process_tii_ssrc_23_logs
from UNSW_NB15 import process_unsw_nb15_logs

def run_dataset(dataset, pcap_path):
    """Run Suricata on a specified dataset and either a single PCAP file or all PCAP files in a folder."""
    dataset_paths = {
        "TII-SSRC-23": "../datasets/TII-SSRC-23",
        "UNSW-NB15": "../datasets/UNSW-NB15"
    }
    
    if dataset not in dataset_paths:
        raise ValueError("Invalid dataset. Choose from: " + ", ".join(dataset_paths.keys()))
    
    full_path = os.path.join(dataset_paths[dataset], "pcap", pcap_path)
    
    # Check if the given path is a file or a folder
    if os.path.isfile(full_path):
        pcap_files = [full_path]  # Process a single file
    elif os.path.isdir(full_path):
        pcap_files = [os.path.join(full_path, f) for f in os.listdir(full_path) if f.endswith(".pcap")]
    else:
        raise FileNotFoundError(f"PCAP file or folder not found: {full_path}")
    
    # Run Suricata on each PCAP file
    for pcap_file in pcap_files:
        print(f"Processing: {pcap_file}")
        
        cmd = ["sudo", "suricata", "-r", pcap_file, "-l", "./logs", "-v"]
        process = subprocess.Popen(cmd)
        process.wait()
        
        process_logs(dataset, pcap_file)

    return dataset, pcap_files

def process_logs(dataset, pcap_file):
    """Process the Suricata logs based on the selected dataset."""
    if dataset == "UNSW-NB15":
        process_unsw_nb15_logs(pcap_file)
    elif dataset == "TII-SSRC-23":
        process_tii_ssrc_23_logs(pcap_file)
    else:
        print(f"No processing logic available for the dataset: {dataset}")

def main():
    parser = argparse.ArgumentParser(description="Run Suricata on a specified dataset and PCAP file/folder.")
    parser.add_argument("dataset", choices=["TII-SSRC-23", "UNSW-NB15"], help="Choose a dataset")
    parser.add_argument("pcap_path", help="Specify a PCAP file or folder name within the dataset")
    args = parser.parse_args()
    run_dataset(args.dataset, args.pcap_path)

if __name__ == "__main__":
    main()
