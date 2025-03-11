import pandas as pd
import os
import sys

def process_tii_ssrc_23_logs(pcap_file):
    pd.set_option('future.no_silent_downcasting', True)
    
    pcap_to_gt_map = {
    "../datasets/TII-SSRC-23/pcap/http.pcap": "../datasets/TII-SSRC-23/ground_truth/Video HTTP.csv",
    "../datasets/TII-SSRC-23/pcap/bruteforce_http.pcap": "../datasets/TII-SSRC-23/ground_truth/Bruteforce HTTP.csv",
    "../datasets/TII-SSRC-23/pcap/udp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS UDP.csv",
    "../datasets/TII-SSRC-23/pcap/mirai_ddos_syn.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS SYN.csv",
    "../datasets/TII-SSRC-23/pcap/mirai_ddos_syn.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS SYN.csv",


    }

    gt_path = pcap_to_gt_map.get(pcap_file) # , low_memory=False

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
    "Protocol": "proto",
    "Label": "flow_alerted",
    }

    df_gt.rename(columns=column_mapping, inplace=True)
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({'Benign': False, 'Malicious': True})
    df_gt['proto'] = df_gt['proto'].replace({6.0: 'tcp', 17.0: 'udp', 0.0: 'hopopt'})

    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce')
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce')


    conn_log_file = './conn.log'
    notice_log_file = './notice.log'
    
    if not os.path.exists(conn_log_file and notice_log_file):
        print(f"Zeek log files not found for {pcap_file}. Skipping...")
        sys.exit()
    
    notice_df = pd.read_json('./notice.log', lines=True)
    conn_df = pd.read_json('./conn.log', lines=True)
    notice_df = notice_df[["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]]
    notice_df["flow_alerted"] = True  

    conn_df = conn_df[["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]]

    notice_df.rename(columns={
        "id.orig_h": "src_ip",
        "id.orig_p": "src_port",
        "id.resp_h": "dest_ip",
        "id.resp_p": "dest_port"
    }, inplace=True)

    conn_df.rename(columns={
        "id.orig_h": "src_ip",
        "id.orig_p": "src_port",
        "id.resp_h": "dest_ip",
        "id.resp_p": "dest_port"
    }, inplace=True)

    


    df_zeek = pd.merge(conn_df, notice_df, how='left', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'])
    df_zeek["flow_alerted"] = df_zeek["flow_alerted"].fillna(False)



    df_merged = pd.merge(df_gt, df_zeek, how='left', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'],suffixes=('_gt', '_zeek'))

    df_merged.to_csv("merged.csv", index=False) 
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


