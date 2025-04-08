import pandas as pd
import os
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
    
    df_gt['start_time'] = df_gt['start_time'].apply(lambda x: int(datetime.strptime(x.split('.')[0], '%Y-%m-%d %H:%M:%S').timestamp() + 7200) if pd.notnull(x) else None)    
    log_file = './logs/alert_csv.txt'

    if not os.path.exists(log_file):
        print(f"Snort3 log file not found for {pcap_file}. Skipping...")
        return
    
    column_names = ["timestamp", "pkt_num", "proto", "pkt_gen", "pkt_len", "dir", "src_ap", "dst_ap", "rule", "action", "msg", "class", "start_time"]

    # Load the Snort alert CSV file
    df_snort = pd.read_csv(log_file, names=column_names, header=None)

    # Rename 'action' to 'flow_alerted' and set it to True
    df_snort.rename(columns={'action': 'flow_alerted'}, inplace=True)
    df_snort['flow_alerted'] = True  # Set all values in flow_alerted to True

    # Split 'src_ap' and 'dst_ap' into IP and Port
    df_snort[['src_ip', 'src_port']] = df_snort['src_ap'].str.split(':', n=1, expand=True)
    df_snort[['dest_ip', 'dest_port']] = df_snort['dst_ap'].str.split(':', n=1, expand=True)

    # Convert ports to integers for consistency
    df_snort['src_port'] = pd.to_numeric(df_snort['src_port'], errors='coerce').astype("Int64")
    df_snort['dest_port'] = pd.to_numeric(df_snort['dest_port'], errors='coerce').astype("Int64")
    df_snort['src_ip'] = df_snort['src_ip'].str.strip()
    df_snort['dest_ip'] = df_snort['dest_ip'].str.strip()
    df_snort['proto'] = df_snort['proto'].str.strip().str.lower()

    # Keep only the necessary columns
    df_snort = df_snort[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time', 'flow_alerted']]  # Keep only necessary columns
    df_snort = df_snort.drop_duplicates(subset=["src_ip", "src_port", "dest_ip", "dest_port", "proto", "start_time"])

    df_merged = pd.merge(df_gt, df_snort, how='left', on=['src_ip','src_port','dest_ip','dest_port','proto', 'start_time'],suffixes=('_gt', '_snort'))
    df_merged['flow_alerted_snort'] = df_merged['flow_alerted_snort'].fillna(False)
    
    df_gt.to_csv("./tmp/df_gt.csv")
    df_snort.to_csv("./tmp/df_snort.csv")
    df_merged.to_csv("./tmp/df_merged.csv")
    
    df_tp = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_snort"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_snort"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_snort"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_snort"] == False)]
    
    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0

    tot_true_pos += len(df_tp)
    tot_false_pos += len(df_fp)
    tot_false_neg += len(df_fn)
    tot_true_neg += len(df_tn)

    return(tot_true_pos, tot_false_pos,tot_false_neg,tot_true_neg)