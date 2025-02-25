import pandas as pd


def process_unsw_nb15_logs(pcap_file):
    

    gt_path = '../datasets/UNSW-NB15/ground_truth/ground_truth.csv'
    df_gt = pd.read_csv(gt_path) 


    column_mapping = {
    "srcip": "src_ip",
    "sport": "src_port",
    "dstip": "dest_ip",
    "dsport": "dest_port",
    "Label": "flow_alerted",
    }

    df_gt.rename(columns=column_mapping, inplace=True)

    df_gt = df_gt[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'flow_alerted']]  # Keep only necessary columns
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({0: False, 1: True})

    df_suricata = pd.read_json('./logs/eve.json', lines=True)
    df_suricata = df_suricata[df_suricata['event_type'] == 'flow']
    df_suricata["flow_alerted"] = df_suricata["flow"].apply(lambda x: x.get("alerted", False) if isinstance(x, dict) else False)

    df_suricata = df_suricata[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'flow_alerted']]  # Keep only necessary columns
    df_suricata['proto'] = df_suricata['proto'].str.lower()

    #df_suricata.to_csv('df_suricata',index=False)
    #df_gt.to_csv('df_gt',index=False)

    

    df_merged = pd.merge(df_gt, df_suricata, how='inner', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto'])

    #df_merged = df_merged.drop_duplicates(subset=['src_port'], keep='first')

    #df_merged.to_csv('df_merged',index=False)
    df_tp = df_merged[(df_merged["flow_alerted_x"] == True) & (df_merged["flow_alerted_y"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_x"] == False) & (df_merged["flow_alerted_y"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_x"] == False) & (df_merged["flow_alerted_y"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_x"] == True) & (df_merged["flow_alerted_y"] == False)]
    
    print(f"Pcap file with path: {pcap_file}")
    print(f"True positives: {len(df_tp)}")
    print(f"False positives: {len(df_fp)}")
    print(f"True negatives: {len(df_tn)}")
    print(f"False negatives: {len(df_fn)}")

    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0


    tot_true_pos += len(df_tp)
    tot_false_pos += len(df_fp)
    tot_false_neg += len(df_fn)
    tot_true_neg += len(df_tn)
    
    print("=====================================")
    print(f"Total True positives: {tot_true_pos}")
    print(f"Total False positives: {tot_false_pos}")
    print(f"Total False negatives: {tot_false_neg}")
    print(f"Total True negatives: {tot_true_neg}")

    accuracy = (tot_true_pos + tot_true_neg) / (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) if (tot_true_pos + tot_true_neg + tot_false_pos + tot_false_neg) != 0 else 0
    recall = tot_true_pos / (tot_true_pos + tot_false_neg) if (tot_true_pos + tot_false_neg) != 0 else 0
    precision = tot_true_pos / (tot_true_pos + tot_false_pos) if (tot_true_pos + tot_false_pos) != 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if precision + recall != 0 else 0

    print(f"Accuracy: {accuracy}")
    print(f"Recall: {recall}")
    print(f"Precision: {precision}")
    print(f"F1 score: {f1}")
