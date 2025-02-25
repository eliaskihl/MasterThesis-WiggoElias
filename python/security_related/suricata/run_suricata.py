import subprocess
import argparse
import os
import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from TII_SSRC_23 import process_tii_ssrc_23_logs
from UNSW_NB15 import process_unsw_nb15_logs


def run_dataset(dataset, pcap_name):
    """Run Suricata on a specified dataset and PCAP file."""
    # Define dataset base paths
    dataset_paths = {
        "TII-SSRC-23": "../datasets/TII-SSRC-23",
        "UNSW-NB15": "../datasets/UNSW-NB15"
    }
    
    if dataset not in dataset_paths:
        raise ValueError("Invalid dataset. Choose from: " + ", ".join(dataset_paths.keys()))
    
    pcap_file = os.path.join(dataset_paths[dataset], "pcap", pcap_name)
    
    if not os.path.isfile(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
    
    """Run Suricata on the provided PCAP file."""
    cmd = ["sudo", "suricata", "-r", pcap_file, "-l", "./logs", "-v"]
    process = subprocess.Popen(cmd)  
    process.wait()
    
    process_logs(dataset, pcap_file)
    return dataset, pcap_name


def main():
    parser = argparse.ArgumentParser(description="Run Suricata on a specified dataset and PCAP file.")
    parser.add_argument("dataset", choices=["TII-SSRC-23", "UNSW-NB15"], help="Choose a dataset")
    parser.add_argument("pcap_name", help="Specify the PCAP file name within the dataset")
    args = parser.parse_args()
    run_dataset(args.dataset, args.pcap_name)

def process_logs(dataset, pcap_file):
    """Process the Suricata logs based on the selected dataset."""
    if dataset == "UNSW-NB15":
        process_unsw_nb15_logs(pcap_file)
    elif dataset == "TII-SSRC-23":
        process_tii_ssrc_23_logs(pcap_file)
    else:
        print(f"No processing logic available for the dataset: {dataset}")


if __name__ == "__main__":
    main()