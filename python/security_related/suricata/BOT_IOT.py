import pandas as pd
import os

def process_bot_iot_logs(pcap_file):
    pd.set_option('future.no_silent_downcasting', True)
    pcap_to_gt_map = {
    "../datasets/BOT-IOT/pcap/keylogging.pcap": "../datasets/BOT-IOT/ground_truth/keylogging.csv",
    "../datasets/BOT-IOT/pcap/data_exfiltration.pcap": "../datasets/BOT-IOT/ground_truth/data_exfiltration.csv",
}
    gt_path = pcap_to_gt_map.get(pcap_file) # , low_memory=False
    if gt_path:
        df_gt = pd.read_csv(gt_path, delimiter=';')  
    else:
        print(f"No ground truth found for PCAP: {pcap_file}")
 
    column_mapping = {
    "saddr": "src_ip",
    "sport": "src_port",
    "daddr": "dest_ip",
    "dport": "dest_port",
    "stime" : "timestamp",
    "attack": "flow_alerted",
    }

    df_gt.rename(columns=column_mapping, inplace=True)
    df_gt = df_gt[['timestamp', 'proto', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'flow_alerted']]
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({0: False, 1: True})

    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce').astype('Int64')
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce').astype('Int64')

    log_file = './eve.json'
    if not os.path.exists(log_file):
        print(f"Suricata log file not found for {pcap_file}. Skipping...")
        return
    
    df_suricata = pd.read_json(log_file, lines=True)
    df_suricata = df_suricata[df_suricata['event_type'] == 'flow']
    df_suricata["flow_alerted"] = df_suricata["flow"].apply(lambda x: x.get("alerted", False) if isinstance(x, dict) else False)

    df_suricata = df_suricata[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'flow_alerted']]  # Keep only necessary columns
    df_suricata['proto'] = df_suricata['proto'].str.lower()
    df_suricata["src_port"] = pd.to_numeric(df_suricata["src_port"], errors="coerce").fillna(0).astype(int)
    df_suricata["dest_port"] = pd.to_numeric(df_suricata["dest_port"], errors="coerce").fillna(0).astype(int)




    df_merged = pd.merge(df_gt, df_suricata, how='left', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'],suffixes=('_gt', '_suricata'))
    df_merged['flow_alerted_suricata'] = df_merged['flow_alerted_suricata'].fillna(False)
    
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


