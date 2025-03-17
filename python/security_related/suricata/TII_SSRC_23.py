import pandas as pd


def process_tii_ssrc_23_logs(pcap_file):

    pcap_to_gt_map = {
    "../datasets/TII-SSRC-23/pcap/http.pcap": "../datasets/TII-SSRC-23/ground_truth/Video HTTP.csv",
    "../datasets/TII-SSRC-23/pcap/bruteforce_http.pcap": "../datasets/TII-SSRC-23/ground_truth/Bruteforce HTTP.csv",
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
    "Protocol": "proto",
    "Label": "flow_alerted",
    }

    df_gt.rename(columns=column_mapping, inplace=True)


    df_gt = df_gt[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'timestamp', 'proto', 'flow_alerted']]  # Keep only necessary columns

    pd.set_option('future.no_silent_downcasting', True)

    # Your replace operation
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({'Benign': False, 'Malicious': True})
    df_gt['proto'] = df_gt['proto'].replace({6.0: 'tcp', 17.0: 'udp', 0.0: 'hopopt'})
    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce').astype('Int64')
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce').astype('Int64')

    df_suricata = pd.read_json('./eve.json', lines=True)
    df_suricata = df_suricata[df_suricata['event_type'] == 'flow']
    df_suricata["flow_alerted"] = df_suricata["flow"].apply(lambda x: x.get("alerted", False) if isinstance(x, dict) else False)

    df_suricata = df_suricata[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'timestamp', 'proto', 'flow_alerted']]  # Keep only necessary columns
    df_suricata['src_port'] = pd.to_numeric(df_suricata['src_port'], errors='coerce').astype('Int64')
    df_suricata['dest_port'] = pd.to_numeric(df_suricata['dest_port'], errors='coerce').astype('Int64')
    df_suricata['proto'] = df_suricata['proto'].str.lower()


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
