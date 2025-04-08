import subprocess
import argparse
import os
from tabulate import tabulate
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from TII_SSRC_23 import process_tii_ssrc_23_logs
from UNSW_NB15 import process_unsw_nb15_logs
from BOT_IOT import process_bot_iot_logs
from CIC_IDS2017 import process_cic_ids2017_logs
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
from dotenv import load_dotenv, find_dotenv



def run_dataset(dataset, pcap_path):
    #dotenv_path = find_dotenv()
    #load_dotenv(dotenv_path)
    #snort_path = os.getenv("SNORT_PATH")

    dataset_paths = {
        "TII-SSRC-23": "../datasets/TII-SSRC-23",
        "UNSW-NB15": "../datasets/UNSW-NB15",
        "BOT-IOT": "../datasets/BOT-IOT",
        "CIC-IDS2017": "../datasets/CIC-IDS2017"
    }
    
    if dataset not in dataset_paths:
        raise ValueError("Invalid dataset. Choose from: " + ", ".join(dataset_paths.keys()))
    
    full_path = os.path.join(dataset_paths[dataset], "pcap", pcap_path)
    
    if os.path.isfile(full_path):
        pcap_files = [full_path]  
    elif os.path.isdir(full_path):
        pcap_files = [os.path.join(full_path, f) for f in os.listdir(full_path) if f.endswith(".pcap")]
    else:
        raise FileNotFoundError(f"PCAP file or folderprocess_cic_ids2017_logs not found: {full_path}")

    # If multiple PCAP files exist, merge them
    if len(pcap_files) > 1:
        merged_pcap = "./logs/merged.pcap"
        merge_cmd = ["mergecap", "-w", merged_pcap] + pcap_files
        subprocess.run(merge_cmd, check=True)
        pcap_files = [merged_pcap]  # Now only process the merged PCAP

    # Run Snort on the merged PCAP file
    pcap_file = pcap_files[0]
    print(f"\nRunning Snort3\n")
    print(f"Dataset: {dataset}")
    print(f"Pcap: {pcap_path}")
    print("Processing..")
    temp = open(f"./tmp/temp.log", "w")
    err = open(f"./tmp/err.log", "w")

    command = [
        "sudo", 
        "docker", 
        "exec", 
        "snort-container", 
        "bash", 
        "-c",  
        f"cd bin && ./snort -r ../{pcap_file} -c ../etc/snort/snort.lua -l ../../logs && cd .. && cd .. && cd logs && chmod a+r alert_csv.txt"  
    ]
    
    process = subprocess.Popen(command,stdout=temp, stderr=err)
    process.wait()
    process_logs(dataset, pcap_file)

    return dataset, pcap_files

def process_logs(dataset, pcap_file):
    """Process the Snort logs based on the selected dataset."""
    if dataset == "UNSW-NB15":
        tot_true_pos, tot_false_pos, tot_false_neg, tot_true_neg = process_unsw_nb15_logs(pcap_file)
    elif dataset == "TII-SSRC-23":
        tot_true_pos, tot_false_pos, tot_false_neg, tot_true_neg = process_tii_ssrc_23_logs(pcap_file)
    elif dataset == "BOT-IOT":
        tot_true_pos, tot_false_pos, tot_false_neg, tot_true_neg = process_bot_iot_logs(pcap_file)
    elif dataset == "CIC-IDS2017":
        tot_true_pos, tot_false_pos, tot_false_neg, tot_true_neg = process_cic_ids2017_logs(pcap_file)
    else:
        print(f"No processing logic available for the dataset: {dataset}")
    
    accuracy = (tot_true_pos + tot_true_neg) / (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) if (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) != 0 else 0
    recall = tot_true_pos / (tot_true_pos + tot_false_neg) if (tot_true_pos + tot_false_neg) != 0 else 0
    precision = tot_true_pos / (tot_true_pos + tot_false_pos) if (tot_true_pos + tot_false_pos) != 0 else 0
    false_positive_rate = tot_false_pos / (tot_false_pos + tot_true_neg) if tot_false_pos != 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if precision + recall != 0 else 0

    print_statistics(pcap_file, tot_true_pos, tot_false_pos, tot_false_neg, tot_true_neg, accuracy, recall, precision, f1, false_positive_rate)

def print_statistics(pcap_file, tot_true_pos, tot_false_pos, tot_false_neg, tot_true_neg, accuracy, recall, precision, f1, false_positive_rate):
    
    table = [
        ["True Positives", tot_true_pos],
        ["False Positives", tot_false_pos],
        ["False Negatives", tot_false_neg],
        ["True Negatives", tot_true_neg],
        ["Accuracy", f"{accuracy:.4f}"],
        ["Recall (TPR)", f"{recall:.4f}"],
        ["FPR", f"{false_positive_rate:.4f}"],
        ["Precision", f"{precision:.4f}"],
        ["F1 Score", f"{f1:.4f}"]
    ]

    print("=" * 40)
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))

    # Initialize lists to store metrics
    list_acc, list_recall, list_precision, list_f1 = [], [], [], []
    list_acc.append(accuracy)
    list_recall.append(recall)
    list_precision.append(precision)
    list_f1.append(f1)
    
    # Visualize with seaborn
    # cm = np.array([[tot_true_pos, tot_false_neg],[tot_false_pos, tot_true_neg]])
    # labels = ['True Pos','False Neg','False Pos','True Neg']
    # labels = np.asarray(labels).reshape(2,2)
    # sns.heatmap(cm, annot=True, fmt='', cmap='Blues')
    # plt.xlabel("Predicted")
    # plt.ylabel("Actual")
    # plt.show()
    # plt.plot(list_acc, label='Accuracy')
    # plt.plot(list_recall, label='Recall')
    # plt.plot(list_precision, label='Precision')
    # plt.plot(list_f1, label='F1 score')
    # plt.legend()
    # plt.xlabel("File num")
    # plt.ylabel("Value")
    # plt.show()

def main():
    parser = argparse.ArgumentParser(description="Run Snort on a specified dataset and PCAP file/folder.")
    parser.add_argument("dataset", choices=["TII-SSRC-23", "UNSW-NB15", "BOT-IOT", "CIC-IDS2017"], help="Choose a dataset")
    parser.add_argument("pcap_path", help="Specify a PCAP file or folder name within the dataset")
    args = parser.parse_args()
    run_dataset(args.dataset, args.pcap_path)

    # Delete files afterwards
    files_to_delete = ["./logs/alert_csv.txt", "./logs/instance_mappings.csv"]
    for file in files_to_delete:
        if os.path.exists(file):  
            os.remove(file)
    
if __name__ == "__main__":
    main()
