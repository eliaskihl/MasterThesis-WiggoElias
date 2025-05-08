import subprocess
import os
from tabulate import tabulate
from .TII_SSRC_23 import process_zeek_logs_TIISSRC23
from .UNSW_NB15 import process_zeek_logs_UNSWNB15
from .BOT_IOT import process_zeek_logs_BOTIOT
from .CIC_IDS2017 import process_zeek_logs_CICIDS2017
from .ID2T import process_zeek_logs_ID2T


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

def run_traffic_generator(traffic_generator, attack):    
    if traffic_generator == 'ID2T':
        print(attack)

        if attack== ('MemcrashedSpooferAttack' or 'DDoSAttack'):
            cmd = [
                "sudo", 
                "docker", 
                "exec", 
                "id2t-container",  
                "bash", 
                "-c",
                f"./id2t -i ../traffic_generators/id2t/input_pcap/smallFlows.pcap -o ../traffic_generators/id2t/output/smallFlows_output.pcap -a {attack} inject.at-timestamp=0 attack.duration=10"
            ]
        else:
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

def run_zeek_dataset(dataset, pcap):
    dataset_mapping = {
        "TII-SSRC-23": "../datasets/TII-SSRC-23",
        "UNSW-NB15": "../datasets/UNSW-NB15",
        "BOT-IOT": "../datasets/BOT-IOT",
        "CIC-IDS2017": "../datasets/CIC-IDS2017"
    }

    if dataset not in dataset_mapping:
        raise ValueError(f"Unknown dataset: {dataset}")
    
    path_to_pcap = os.path.join(dataset_mapping[dataset], "pcap", pcap)

    run_zeek_on_pcap(path_to_pcap)

    # Call appropriate log parser
    if dataset == "UNSW-NB15":
        tp, fp, fn, tn, noAlerts = process_zeek_logs_UNSWNB15(path_to_pcap)
    elif dataset == "TII-SSRC-23":
        tp, fp, fn, tn, noAlerts = process_zeek_logs_TIISSRC23(path_to_pcap)
    elif dataset == "BOT-IOT":
        tp, fp, fn, tn, noAlerts = process_zeek_logs_BOTIOT(path_to_pcap)
    elif dataset == "CIC-IDS2017":
        tp, fp, fn, tn, noAlerts = process_zeek_logs_CICIDS2017(path_to_pcap)
    else:
        raise ValueError(f"No parser for dataset: {dataset}")

    delete_zeek_logs()

    if noAlerts:
        return None
    else:
        return results(tp, fp, fn, tn) | {"dataset": dataset, "pcap": pcap}
    
def run_zeek_traffic_generator(traffic_generator, attack):
    
    run_traffic_generator(traffic_generator, attack)

    if traffic_generator == 'ID2T':
        run_zeek_on_pcap('../traffic_generators/id2t/output/smallFlows_output.pcap')

        tp, fp, fn, tn, noAlerts = process_zeek_logs_ID2T()


    delete_zeek_logs()

    if noAlerts:
        return None
    else:
        return results(tp, fp, fn, tn) | {"dataset": '', "pcap": '', "traffic_generator": traffic_generator, "attack": attack}