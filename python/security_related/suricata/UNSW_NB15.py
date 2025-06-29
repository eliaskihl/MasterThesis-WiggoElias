import os
import pandas as pd
import subprocess
from datetime import datetime
from pathlib import Path

def process_suricata_logs_UNSWNB15(pcap_file):
    pd.set_option('future.no_silent_downcasting', True)

    pcap_folder_to_gt_map = {
        "../datasets/UNSW-NB15/pcap/pcaps_22-1-2015": "../datasets/UNSW-NB15/ground_truth/22-1-2015.csv",
        "../datasets/UNSW-NB15/pcap/pcaps_17-2-2015": "../datasets/UNSW-NB15/ground_truth/17-2-2015.csv",
    }

    pcap_path = Path(pcap_file).resolve()
    gt_path = None
    for folder, gt_csv in pcap_folder_to_gt_map.items():
        if Path(folder).resolve() in pcap_path.parents:
            gt_path = gt_csv
            break

    if gt_path:
        df_gt = pd.read_csv(gt_path, low_memory=False)
    else:
        print(f"No ground truth found for PCAP: {pcap_file}")
        return (0, 0, 0, 0, True)

    column_mapping = {
        "srcip": "src_ip",
        "sport": "src_port",
        "dstip": "dest_ip",
        "dsport": "dest_port",
        "Stime": "start_time",
        "Label": "flow_alerted"
    }

    df_gt.rename(columns=column_mapping, inplace=True)
    df_gt = df_gt[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time', 'flow_alerted']]

    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce').astype("Int64")
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce').astype("Int64")
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({0: False, 1: True})

    log_file = './logs/eve.json'
    if not os.path.exists(log_file):
        print(f"No alerts generated by Suricata")
        return (0, 0, 0, 0, True)

    df_suricata = pd.read_json(log_file, lines=True)
    df_suricata = df_suricata[df_suricata['event_type'] == 'flow']
    df_suricata["flow_alerted"] = df_suricata["flow"].apply(lambda x: x.get("alerted", False) if isinstance(x, dict) else False)
    df_suricata['start_time'] = df_suricata['flow'].apply(lambda x: x.get('start') if isinstance(x, dict) else None)
    df_suricata['start_time'] = df_suricata['start_time'].apply(
        lambda x: round(datetime.strptime(x[:26], '%Y-%m-%dT%H:%M:%S.%f').timestamp() + 3600) if pd.notnull(x) else None
    )

    df_suricata = df_suricata[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time', 'flow_alerted']]
    df_suricata['proto'] = df_suricata['proto'].str.lower()
    df_suricata["src_port"] = pd.to_numeric(df_suricata["src_port"], errors="coerce").astype("Int64")
    df_suricata["dest_port"] = pd.to_numeric(df_suricata["dest_port"], errors="coerce").astype("Int64")

    temp = open(f"./tmp/temp.log", "w")
    err = open(f"./tmp/err.log", "w")
    cmd = [
        "sudo",
        "docker",
        "exec",
        "zeek-container",
        "bash",
        "-c",
        f"cd logs && zeek -C -r ../{pcap_file} ../usr/local/zeek/share/zeek/base/protocols/conn"
    ]

    process = subprocess.Popen(cmd, stdout=temp, stderr=err)
    process.wait()
    zeek_flows = '../zeek/logs/conn.log'

    df_zeek_flows = pd.read_csv(zeek_flows, sep='\t', comment='#', low_memory=False)
    cols = df_zeek_flows.columns.tolist()

    cols[0] = 'start_time'
    cols[2] = 'src_ip'
    cols[3] = 'src_port'
    cols[4] = 'dest_ip'
    cols[5] = 'dest_port'
    cols[6] = 'proto'
    df_zeek_flows.columns = cols

    df_zeek_flows = df_zeek_flows[["src_ip", "src_port", "dest_ip", "dest_port", "proto", "start_time"]]
 
    df_zeek_flows["start_time"] = df_zeek_flows["start_time"].round()


    df_suricata = pd.merge(
        df_zeek_flows,
        df_suricata,
        how='left',
        on=['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time'],
        suffixes=('_zeek_flows', '_suricata')
    )

    df_merged = pd.merge(
        df_gt,
        df_suricata,
        how='inner',
        on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto', 'start_time'],
        suffixes=('_gt', '_suricata')
    )

    df_merged['flow_alerted_suricata'] = df_merged['flow_alerted_suricata'].fillna(False)

    df_gt.to_csv("./tmp/df_gt.csv")
    df_suricata.to_csv("./tmp/df_suricata.csv")
    df_merged.to_csv("./tmp/df_merged.csv")

    df_tp = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_suricata"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_suricata"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_suricata"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_suricata"] == False)]

    return (len(df_tp), len(df_fp), len(df_fn), len(df_tn), False)
