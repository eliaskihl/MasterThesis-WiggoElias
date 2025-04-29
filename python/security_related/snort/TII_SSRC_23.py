import pandas as pd
from datetime import datetime
import os
def process_snort_logs_TIISSRC23(pcap_file):
    pd.set_option('future.no_silent_downcasting', True)

    pcap_to_gt_map = {
            "../datasets/TII-SSRC-23/pcap/benign/audio/audio.pcap": "../datasets/TII-SSRC-23/ground_truth/Audio.csv",
            "../datasets/TII-SSRC-23/pcap/benign/background/background.pcap": "../datasets/TII-SSRC-23/ground_truth/Background.csv",
            "../datasets/TII-SSRC-23/pcap/benign/text/text.pcap": "../datasets/TII-SSRC-23/ground_truth/Text.csv",
            "../datasets/TII-SSRC-23/pcap/benign/video/http.pcap": "../datasets/TII-SSRC-23/ground_truth/Video HTTP.csv",
            "../datasets/TII-SSRC-23/pcap/benign/video/rtp.pcap": "../datasets/TII-SSRC-23/ground_truth/Video RTP.csv",
            "../datasets/TII-SSRC-23/pcap/benign/video/udp.pcap": "../datasets/TII-SSRC-23/ground_truth/Video UDP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_dns.pcap": "../datasets/TII-SSRC-23/ground_truth/Bruteforce DNS.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_ftp.pcap": "../datasets/TII-SSRC-23/ground_truth/Bruteforce FTP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_http.pcap": "../datasets/TII-SSRC-23/ground_truth/Bruteforce HTTP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_ssh.pcap": "../datasets/TII-SSRC-23/ground_truth/Bruteforce SSH.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_telnet.pcap": "../datasets/TII-SSRC-23/ground_truth/Bruteforce Telnet.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/ack_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS ACK.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/cwr_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS CWR.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/ecn_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS ECN.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/fin_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS FIN.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/http_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS HTTP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/icmp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS ICMP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/mac_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS MAC.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/psh_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS PSH.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/rst_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS RST.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/syn_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS SYN.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/udp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS UDP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/dos/urg_tcp_dos.pcap": "../datasets/TII-SSRC-23/ground_truth/DoS URG.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/information-gathering/information_gathering.pcap": "../datasets/TII-SSRC-23/ground_truth/Information Gathering.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_ddos_ack.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS ACK.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_ddos_dns.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS DNS.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_ddos_greeth.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS GREETH.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_ddos_greip.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS GREIP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_ddos_http.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS HTTP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_ddos_syn.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS SYN.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_ddos_udp_udpplain.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai DDoS UDP.csv",
            "../datasets/TII-SSRC-23/pcap/malicious/mirai-botnet/mirai_scan_bruteforce.pcap": "../datasets/TII-SSRC-23/ground_truth/Mirai Scan Bruteforce.csv",
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
    "Timestamp" : "start_time",
    "Protocol": "proto",
    "Label": "flow_alerted",
    }

    df_gt.rename(columns=column_mapping, inplace=True)
    df_gt = df_gt[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time', 'flow_alerted']]  # Keep only necessary columns

    # Your replace operation
    df_gt['flow_alerted'] = df_gt['flow_alerted'].replace({'Benign': False, 'Malicious': True})
    df_gt['proto'] = df_gt['proto'].replace({6.0: 'tcp', 17.0: 'udp', 0.0: 'hopopt'})
    df_gt['src_port'] = pd.to_numeric(df_gt['src_port'], errors='coerce').astype('Int64')
    df_gt['dest_port'] = pd.to_numeric(df_gt['dest_port'], errors='coerce').astype('Int64')
    df_gt['start_time'] = df_gt['start_time'].apply(lambda x: datetime.strptime(x, '%d/%m/%Y %I:%M:%S %p').timestamp() - 10800 if pd.notnull(x) else None)

    column_names = ["timestamp", "pkt_num", "proto", "pkt_gen", "pkt_len", "dir", "src_ap", "dst_ap", "rule", "action", "msg", "class", "start_time"]

    log_file = './logs/alert_csv.txt'
    if not os.path.exists(log_file):
        print(f"No alerts generated by Snort")
        return(0,0,0,0,True)
    
    # Load the Snort alert CSV file
    df_snort = pd.read_csv(log_file, names=column_names, header=None)

    # Rename 'action' to 'flow_alerted' and set it to True
    df_snort.rename(columns={'action': 'flow_alerted'}, inplace=True)
    df_snort['flow_alerted'] = True  # Set all values in flow_alerted to True

    # Split 'src_ap' and 'dst_ap' into IP and Port
    df_snort[['src_ip', 'src_port']] = df_snort['src_ap'].str.split(':', n=1, expand=True)
    df_snort[['dest_ip', 'dest_port']] = df_snort['dst_ap'].str.split(':', n=1, expand=True)

    # Convert ports to integers for consistency
    df_snort['src_port'] = pd.to_numeric(df_snort['src_port'], errors='coerce').astype('Int64')
    df_snort['dest_port'] = pd.to_numeric(df_snort['dest_port'], errors='coerce').astype('Int64')
    df_snort['src_ip'] = df_snort['src_ip'].str.strip()
    df_snort['dest_ip'] = df_snort['dest_ip'].str.strip()
    df_snort['proto'] = df_snort['proto'].str.strip().str.lower()
    
    # Keep only the necessary columns
    df_snort = df_snort[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time', 'flow_alerted']]
    df_snort = df_snort.drop_duplicates(subset=['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'start_time'])


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

    return(tot_true_pos, tot_false_pos,tot_false_neg,tot_true_neg, False)
