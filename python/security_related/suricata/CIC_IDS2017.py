import os
import pandas as pd
from datetime import datetime

def process_cic_ids2017_logs(pcap_file):
    pd.set_option('future.no_silent_downcasting', True)
    
    pcap_to_gt_map = {
    "../datasets/CIC-IDS2017/pcap/Monday-WorkingHours.pcap": "../datasets/CIC-IDS2017/ground_truth/monday.csv",
    "../datasets/CIC-IDS2017/pcap/Tuesday-WorkingHours.pcap": "../datasets/CIC-IDS2017/ground_truth/tuesday.csv",
    "../datasets/CIC-IDS2017/pcap/Wednesday-WorkingHours.pcap": "../datasets/CIC-IDS2017/ground_truth/wednesday.csv",
    }

    gt_path = pcap_to_gt_map.get(pcap_file) 
    if gt_path:
        df_gt = pd.read_csv(gt_path, low_memory=False)  
    else:
        print(f"No ground truth found for PCAP: {pcap_file}")
 
    df_gt.to_csv("df_gt.csv")

    column_mapping = {
    "Src IP": "src_ip",
    "Src Port": "src_port",
    "Dst IP": "dest_ip",
    "Dst Port": "dest_port",
    "Timestamp" : "start_time",
    "Protocol" : "proto",
    "Label": "flow_alerted"
    }

    df_gt.rename(columns=column_mapping, inplace=True)

    df_gt = df_gt[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time', 'flow_alerted']]
    df_gt['flow_alerted'] = df_gt['flow_alerted'].apply(lambda x: False if x == 'BENIGN' else True)
    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce').astype('Int64')
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce').astype('Int64')
    df_gt['proto'] = df_gt['proto'].replace({6: 'tcp', 17: 'udp', 0: 'hopopt'})
    
    # +7200 because of timezone difference 
    df_gt['start_time'] = df_gt['start_time'].apply(lambda x: int(datetime.strptime(x.split('.')[0], '%Y-%m-%d %H:%M:%S').timestamp() + 7200) if pd.notnull(x) else None)    
    df_gt.to_csv("df_gt.csv")

    log_file = './eve.json'
    if not os.path.exists(log_file):
        print(f"Suricata log file not found for {pcap_file}. Skipping...")
        return
    df_suricata = pd.read_json(log_file, lines=True)
    
    df_suricata = df_suricata[df_suricata['event_type'] == 'flow']
    df_suricata["flow_alerted"] = df_suricata["flow"].apply(lambda x: x.get("alerted", False) if isinstance(x, dict) else False)
    df_suricata['start_time'] = df_suricata['flow'].apply(lambda x: x.get('start') if isinstance(x, dict) else None)
    df_suricata['start_time'] = df_suricata['start_time'].apply(lambda x: int(datetime.strptime(x[:19], '%Y-%m-%dT%H:%M:%S').timestamp()) if pd.notnull(x) else None)

    df_suricata = df_suricata[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto','start_time', 'flow_alerted']]  # Keep only necessary columns
    df_suricata['proto'] = df_suricata['proto'].str.lower()
    df_suricata["src_port"] = pd.to_numeric(df_suricata["src_port"], errors="coerce").astype("Int64")
    df_suricata["dest_port"] = pd.to_numeric(df_suricata["dest_port"], errors="coerce").astype("Int64")

    df_merged = pd.merge(df_gt, df_suricata, how='left', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto', 'start_time'],suffixes=('_gt', '_suricata'))
    df_merged['flow_alerted_suricata'] = df_merged['flow_alerted_suricata'].fillna(False)

    # df_suricata.to_csv("df_suricata.csv", index=False) 
    # df_gt.to_csv("df_gt.csv", index=False) 
    # df_merged.to_csv("df_merged.csv", index=False) 

    df_tp = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_suricata"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_suricata"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_suricata"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_suricata"] == False)]
    
    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0

    tot_true_pos += len(df_tp)
    tot_false_pos += len(df_fp)
    tot_false_neg += len(df_fn)
    tot_true_neg += len(df_tn)

    return(tot_true_pos, tot_false_pos,tot_false_neg,tot_true_neg)


