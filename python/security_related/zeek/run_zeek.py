import subprocess
import argparse
import os
from tabulate import tabulate
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from TII_SSRC_23 import process_zeek_logs_TIISSRC23
from UNSW_NB15 import process_zeek_logs_UNSWNB15
from BOT_IOT import process_zeek_logs_BOTIOT
from CIC_IDS2017 import process_zeek_logs_CICIDS2017
from ID2T import process_zeek_logs_ID2T

import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

def run_zeek_on_pcap(pcap):
    temp = open(f"./tmp/temp.log", "w")
    err = open(f"./tmp/err.log", "w")
    cmd = [
        "sudo", 
        "docker", 
        "exec", 
        "zeek-container", 
        "bash", 
        "-c",
        f"cd logs && zeek -C -r ../{pcap} /usr/local/zeek/share/zeek/test-all-policy.zeek" 
    ]

    process = subprocess.Popen(cmd,stdout=temp, stderr=err)
    process.wait()

# Attacks: PortscanAttack
def run_traffic_generator(traffic_generator, attack):    
    if traffic_generator == 'ID2T':
        cmd = [
            "sudo", 
            "docker", 
            "exec", 
            "id2t-container",  
            "bash", 
            "-c",
            f"./id2t -i ../traffic/input_pcap/smallFlows.pcap -o ../traffic/output/smallFlows_output.pcap -a {attack} ip.src=192.168.178.2 mac.src=32:08:24:DC:8D:27 inject.at-timestamp=0"
        ]
        process = subprocess.Popen(cmd)
        process.wait()



def delete_zeek_logs():
    files_in_logs = os.listdir('./logs')
    files_to_delete = [file for file in files_in_logs if file.endswith('.log')]
    for file in files_to_delete:
        file_path = os.path.join('./logs/', file)
        if os.path.exists(file_path):  
            os.remove(file_path)

def results(tp, fp, fn, tn):
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) != 0 else 0
    recall = tp / (tp + fn) if (tp + fn) != 0 else 0
    precision = tp / (tp + fp) if (tp + fp) != 0 else 0
    false_positive_rate = fp / (fp + tn) if fp != 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if precision + recall != 0 else 0

    table = [
        ["True Positives", tp],
        ["False Positives", fp],
        ["False Negatives", fn],
        ["True Negatives", tn],
        ["Accuracy", f"{accuracy:.4f}"],
        ["Recall (TPR)", f"{recall:.4f}"],
        ["FPR", f"{false_positive_rate:.4f}"],
        ["Precision", f"{precision:.4f}"],
        ["F1 Score", f"{f1:.4f}"]
    ]

    print("=" * 40)
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="grid"))

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
    parser = argparse.ArgumentParser(description="Run Zeek with a dataset or traffic generator")
    
    # Create two main option groups
    data_group = parser.add_argument_group("Dataset options")
    data_group.add_argument("--dataset", choices=["TII-SSRC-23", "UNSW-NB15", "BOT-IOT", "CIC-IDS2017"], 
                           help="Choose a dataset")
    data_group.add_argument("--pcap", help="Specify a PCAP file from the dataset")
    
    generator_group = parser.add_argument_group("Traffic generator options")
    generator_group.add_argument("--traffic-generator", choices=["ID2T"], help="Choose a traffic generator")
    generator_group.add_argument("--attack", help="Specify an attack for traffic generation")
    
    args = parser.parse_args()
    
    # To run traffic generators (attacks = DDoS Attack, EternalBlue Exploit, FTPWinaXe Exploit, JoomlaRegPrivesc Exploit, MS17ScanAttack,  
    # Memcrashed Attack (Spoofer side), P2P Botnet Communication (P2PBotnet), Portscan Attack, SMBLoris Attack, SMBScan Attack, SQLi Attack, 
    # Sality Botnet)
    if args.traffic_generator:
        run_traffic_generator(args.traffic_generator, args.attack)
        if args.traffic_generator == 'ID2T':
            run_zeek_on_pcap('../traffic_generators/ID2T/output/smallFlows_output.pcap')
            tp, fp, fn, tn, noAlerts = process_zeek_logs_ID2T()


    # To run datasets
    else:
        dataset_mapping = {
        "TII-SSRC-23": "../datasets/TII-SSRC-23",
        "UNSW-NB15": "../datasets/UNSW-NB15",
        "BOT-IOT": "../datasets/BOT-IOT",
        "CIC-IDS2017": "../datasets/CIC-IDS2017"
        }
        if args.dataset not in dataset_mapping:
            raise ValueError("Invalid dataset. Choose from: " + ", ".join(dataset_mapping.keys()))
        
        path_to_pcap = os.path.join(dataset_mapping[args.dataset], "pcap", args.pcap)
        
        run_zeek_on_pcap(path_to_pcap)
        
        if args.dataset == "UNSW-NB15":
            tp, fp, fn, tn, noAlerts = process_zeek_logs_UNSWNB15(path_to_pcap)
        elif args.dataset == "TII-SSRC-23":
            tp, fp, fn, tn, noAlerts = process_zeek_logs_TIISSRC23(path_to_pcap)
        elif args.dataset == "BOT-IOT":
            tp, fp, fn, tn, noAlerts = process_zeek_logs_BOTIOT(path_to_pcap)
        elif args.dataset == "CIC-IDS2017":
            tp, fp, fn, tn, noAlerts = process_zeek_logs_CICIDS2017(path_to_pcap)
        else:
            print(f"No processing logic available for the dataset: {args.dataset}")
    
    delete_zeek_logs()

    if noAlerts: 
        return
    else:
        results(tp, fp, fn, tn)


if __name__ == "__main__":
    main()