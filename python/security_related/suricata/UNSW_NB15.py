
import pandas as pd
import os

def process_unsw_nb15_logs(pcap_file):
    
    gt_path = '../datasets/UNSW-NB15/ground_truth/ground_truth.csv'
    df_gt = pd.read_csv(gt_path, low_memory=False) 

    column_mapping = {
    "srcip": "src_ip",
    "sport": "src_port",
    "dstip": "dest_ip",
    "dsport": "dest_port",
    "Label": "flow_alerted",
    }

    df_gt.rename(columns=column_mapping, inplace=True)

    df_gt = df_gt[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'flow_alerted']]  # Keep only necessary columns

    pd.set_option('future.no_silent_downcasting', True)
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({0: False, 1: True})
    df_gt["src_port"] = pd.to_numeric(df_gt["src_port"], errors="coerce").fillna(0).astype(int)
    df_gt["dest_port"] = pd.to_numeric(df_gt["dest_port"], errors="coerce").fillna(0).astype(int)

    log_file = './logs/eve.json'
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

    df_merged = pd.merge(df_gt, df_suricata, how='inner', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'])
    #df_merged.to_csv("merged.csv", index=False) 

    df_tp = df_merged[(df_merged["flow_alerted_x"] == True) & (df_merged["flow_alerted_y"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_x"] == False) & (df_merged["flow_alerted_y"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_x"] == False) & (df_merged["flow_alerted_y"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_x"] == True) & (df_merged["flow_alerted_y"] == False)]
    
    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0

    tot_true_pos += len(df_tp)
    tot_false_pos += len(df_fp)
    tot_false_neg += len(df_fn)
    tot_true_neg += len(df_tn)

    return(tot_true_pos, tot_false_pos,tot_false_neg,tot_true_neg)

