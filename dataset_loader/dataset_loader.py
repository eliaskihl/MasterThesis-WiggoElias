import os 
import pandas as pd

def load_dataset(pcap_path: str, ground_truth_path: str):
    """Load PCAP file and ground truth labels."""
    if not os.path.exists(pcap_path) or not os.path.exists(ground_truth_path):
        raise FileNotFoundError("Dataset files not found!")

    ground_truth = pd.read_csv(ground_truth_path)  # Assuming CSV format
    return pcap_path, ground_truth



pcap_file, ground_truth = load_dataset("dataset.pcap", "ground_truth.csv")