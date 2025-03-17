import pandas as pd
import os
import sys

def process_cic_ids2017_logs(pcap_file):
    pd.set_option('future.no_silent_downcasting', True)
    
    pcap_to_gt_map = {
    "../datasets/CIC-IDS2017/pcap/Monday-WorkingHours.pcap": "../datasets/CIC-IDS2017/ground_truth/monday.csv",
    "../datasets/CIC-IDS2017/pcap/Tuesday-WorkingHours.pcap": "../datasets/CIC-IDS2017/ground_truth/tuesday.csv",
    "../datasets/CIC-IDS2017/pcap/Wednesday-WorkingHours.pcap": "../datasets/CIC-IDS2017/ground_truth/wednesday.csv",
    }

    gt_path = pcap_to_gt_map.get(pcap_file) 
    if gt_path:
        df_gt = pd.read_csv(gt_path)  
    else:
        print(f"No ground truth found for PCAP: {pcap_file}")
 
    
    column_mapping = {
    "Src IP": "src_ip",
    "Src Port": "src_port",
    "Dst IP": "dest_ip",
    "Dst Port": "dest_port",
    "Timestamp" : "timestamp",
    "Protocol" : "proto",
    "Label": "flow_alerted"
    }

    df_gt.rename(columns=column_mapping, inplace=True)
    df_gt = df_gt[['timestamp', 'proto', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'flow_alerted']]
    df_gt['flow_alerted'] = df_gt['flow_alerted'].apply(lambda x: False if x == 'BENIGN' else True)

    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce').astype('Int64')
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce').astype('Int64')
    df_gt['proto'] = df_gt['proto'].replace({6: 'tcp', 17: 'udp', 0: 'hopopt'})

    notice_log_file = './notice.log'
    
    if not os.path.exists(notice_log_file):
        print(f"Zeek log files not found for {pcap_file}. Skipping...")
        sys.exit()
    
    notice_df = pd.read_json('./notice.log', lines=True)
    notice_df = notice_df[["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]]
    notice_df["flow_alerted"] = True  

    notice_df.rename(columns={
        "id.orig_h": "src_ip",
        "id.orig_p": "src_port",
        "id.resp_h": "dest_ip",
        "id.resp_p": "dest_port"
    }, inplace=True)

    notice_df['src_port'] = pd.to_numeric(notice_df['src_port'], errors='coerce').astype('Int64')
    notice_df['dest_port'] = pd.to_numeric(notice_df['dest_port'], errors='coerce').astype('Int64')

    # notice_df.to_csv("notice_df.csv")
    # df_gt.to_csv("df_gt.csv")

    df_merged = pd.merge(df_gt, notice_df, how='left', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'],suffixes=('_gt', '_zeek'))
    df_merged["flow_alerted_zeek"] = df_merged["flow_alerted_zeek"].fillna(False)

    # df_merged.to_csv("df_merged.csv")

    df_tp = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_zeek"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_zeek"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_zeek"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_zeek"] == False)]
    
    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0

    tot_true_pos += len(df_tp)
    tot_false_pos += len(df_fp)
    tot_false_neg += len(df_fn)
    tot_true_neg += len(df_tn)

    return(tot_true_pos, tot_false_pos,tot_false_neg,tot_true_neg)


