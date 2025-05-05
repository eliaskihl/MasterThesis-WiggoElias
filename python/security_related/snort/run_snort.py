import subprocess
import os
from tabulate import tabulate
from .TII_SSRC_23 import process_snort_logs_TIISSRC23
from .UNSW_NB15 import process_snort_logs_UNSWNB15
from .BOT_IOT import process_snort_logs_BOTIOT
from .CIC_IDS2017 import process_snort_logs_CICIDS2017
from .ID2T import process_snort_logs_ID2T

def run_snort_on_pcap(pcap):
    temp = open(f"./tmp/temp.log", "w")
    err = open(f"./tmp/err.log", "w")
    cmd = ["sudo", 
    "docker", 
    "exec", 
    "snort-container", 
    "bash", 
    "-c",  
    f"cd bin && ./snort -r ../{pcap} -c ../etc/snort/snort.lua -l ../../logs"]

    process = subprocess.Popen(cmd,stdout=temp, stderr=err)
    process.wait()


    # Set permissions regardless of snort success
    cmd_chmod = [
        "sudo", "docker", "exec", "snort-container", "bash", "-c",
        "chmod a+r ../logs/alert_csv.txt"
    ]
    subprocess.run(cmd_chmod)


def run_traffic_generator(traffic_generator, attack):    
    if traffic_generator == 'ID2T':
        cmd = [
            "sudo", 
            "docker", 
            "exec", 
            "id2t-container",  
            "bash", 
            "-c",
            f"./id2t -i ../traffic_generators/id2t/input_pcap/smallFlows.pcap -o ../traffic_generators/id2t/output/smallFlows_output.pcap -a {attack} inject.at-timestamp=0"
        ]
        process = subprocess.Popen(cmd)
        process.wait()


def delete_snort_logs():
    files_to_delete = ["./logs/alert_csv.txt", "./logs/instance_mappings.csv"]
    for file in files_to_delete:
        if os.path.exists(file):  
            os.remove(file)

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
    
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "Accuracy": accuracy,
        "Recall": recall,
        "FPR": false_positive_rate,
        "Precision": precision,
        "F1": f1
    }

def run_snort_dataset(dataset, pcap):
    dataset_mapping = {
        "TII-SSRC-23": "../datasets/TII-SSRC-23",
        "UNSW-NB15": "../datasets/UNSW-NB15",
        "BOT-IOT": "../datasets/BOT-IOT",
        "CIC-IDS2017": "../datasets/CIC-IDS2017"
    }

    if dataset not in dataset_mapping:
        raise ValueError(f"Unknown dataset: {dataset}")

    path_to_pcap = os.path.join(dataset_mapping[dataset], "pcap", pcap)

    run_snort_on_pcap(path_to_pcap)

    # Call appropriate log parser
    if dataset == "UNSW-NB15":
        tp, fp, fn, tn, noAlerts = process_snort_logs_UNSWNB15(path_to_pcap)
    elif dataset == "TII-SSRC-23":
        tp, fp, fn, tn, noAlerts = process_snort_logs_TIISSRC23(path_to_pcap)
    elif dataset == "BOT-IOT":
        tp, fp, fn, tn, noAlerts = process_snort_logs_BOTIOT(path_to_pcap)
    elif dataset == "CIC-IDS2017":
        tp, fp, fn, tn, noAlerts = process_snort_logs_CICIDS2017(path_to_pcap)
    else:
        raise ValueError(f"No parser for dataset: {dataset}")

    delete_snort_logs()

    if noAlerts:
        return None
    else:
        return results(tp, fp, fn, tn) | {"dataset": dataset, "pcap": pcap, "traffic_generator": '', "attack": ''}

def run_snort_traffic_generator(traffic_generator, attack):
    
    run_traffic_generator(traffic_generator, attack)

    if traffic_generator == 'ID2T':
        run_snort_on_pcap('../traffic_generators/id2t/output/smallFlows_output.pcap')

        tp, fp, fn, tn, noAlerts = process_snort_logs_ID2T()


    delete_snort_logs()

    if noAlerts:
        return None
    else:
        return results(tp, fp, fn, tn) | {"dataset": '', "pcap": '', "traffic_generator": traffic_generator, "attack": attack}