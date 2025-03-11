import pandas as pd
import os


def process_unsw_nb15_logs(pcap_file):
    pd.set_option('future.no_silent_downcasting', True)
    pcap_to_gt_map = {
    "../datasets/UNSW-NB15/pcap/1.pcap": "../datasets/UNSW-NB15/ground_truth/ground_truth_1.csv",
    "../datasets/UNSW-NB15/pcap/2.pcap": "../datasets/UNSW-NB15/ground_truth/ground_truth_2.csv",
}
    gt_path = pcap_to_gt_map.get(pcap_file)  

    if gt_path:
        df_gt = pd.read_csv(gt_path)  
    else:
        print(f"No ground truth found for PCAP: {pcap_file}")
    df_gt = pd.read_csv(gt_path, low_memory=False) 

    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce')
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce')

    conn_log_file = './conn.log'
    notice_log_file = './notice.log'
    
    if not os.path.exists(conn_log_file and notice_log_file):
        print(f"Zeek log files not found for {pcap_file}. Skipping...")
        return
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

    


    df_zeek = pd.merge(conn_df, notice_df, how='left', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'],suffixes=('_conn', '_notice'))
    df_zeek["flow_alerted"] = df_zeek["flow_alerted"].fillna(False)



    df_merged = pd.merge(df_gt, df_zeek, how='left', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'],suffixes=('_gt', '_suricata'))
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


