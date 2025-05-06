import os
import pandas as pd
import subprocess
from datetime import datetime

def process_suricata_logs_TIISSRC23(pcap_file):
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
    df_gt['start_time'] = df_gt['start_time'].apply(lambda x: int(datetime.strptime(x, '%d/%m/%Y %I:%M:%S %p').timestamp() - 10800) if pd.notnull(x) else None)
    
    log_file = './logs/eve.json'
    if not os.path.exists(log_file):
        print(f"No alerts generated by Suricata")
        return(0,0,0,0,True)
    df_suricata = pd.read_json(log_file, lines=True)
    df_suricata = df_suricata[df_suricata['event_type'] == 'flow']
    df_suricata["flow_alerted"] = df_suricata["flow"].apply(lambda x: x.get("alerted", False) if isinstance(x, dict) else False)

    df_suricata['start_time'] = df_suricata['flow'].apply(lambda x: x.get('start') if isinstance(x, dict) else None)
    df_suricata['start_time'] = df_suricata['start_time'].apply(lambda x: int(datetime.strptime(x[:19], '%Y-%m-%dT%H:%M:%S').timestamp() + 3600) if pd.notnull(x) else None)

    df_suricata = df_suricata[['src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto','start_time', 'flow_alerted']]  # Keep only necessary columns
    df_suricata['proto'] = df_suricata['proto'].str.lower()
    df_suricata["src_port"] = pd.to_numeric(df_suricata["src_port"], errors="coerce").astype("Int64")
    df_suricata["dest_port"] = pd.to_numeric(df_suricata["dest_port"], errors="coerce").astype("Int64")

    # Using zeek here to extract all the flows from the pcap file 
    temp = open(f"./tmp/temp.log", "w")
    err = open(f"./tmp/err.log", "w")
    cmd = [
        "sudo", 
        "docker", 
        "exec", 
        "zeek-container", 
        "bash", 
        "-c",
        f"cd logs && zeek -C -r ../{pcap_file} ../usr/local/zeek/share/zeek/base/protocols/conn" 
    ]

    process = subprocess.Popen(cmd,stdout=temp, stderr=err)
    process.wait()
    zeek_flows = '../zeek/logs/conn.log'


    df_zeek_flows = pd.read_csv(zeek_flows, sep='\t', comment='#', low_memory=False)
    cols = df_zeek_flows.columns.tolist()

    cols[0] = 'start_time'
    cols[2] = 'src_ip'
    cols[3] = 'src_port'
    cols[4] = 'dest_ip'
    cols[5] = 'dest_port'
    cols[6] = 'proto'
    df_zeek_flows.columns = cols

    df_zeek_flows = df_zeek_flows[["src_ip", "src_port", "dest_ip", "dest_port", "proto", "start_time"]]
    df_zeek_flows["start_time"] = df_zeek_flows["start_time"].astype(int)


    df_suricata = pd.merge(df_zeek_flows, df_suricata, how='left', on=['src_ip','src_port','dest_ip','dest_port','proto', 'start_time'],suffixes=('_zeek_flows', '_suricata'))

    df_merged = pd.merge(df_gt, df_suricata, how='inner', on=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'proto', 'start_time'],suffixes=('_gt', '_suricata'))
    df_merged['flow_alerted_suricata'] = df_merged['flow_alerted_suricata'].fillna(False)

    df_gt.to_csv("./tmp/df_gt.csv")
    df_suricata.to_csv("./tmp/df_suricata.csv")
    df_merged.to_csv("./tmp/df_merged.csv")

    df_tp = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_suricata"] == True)]
    df_tn = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_suricata"] == False)]
    df_fp = df_merged[(df_merged["flow_alerted_gt"] == False) & (df_merged["flow_alerted_suricata"] == True)]
    df_fn = df_merged[(df_merged["flow_alerted_gt"] == True) & (df_merged["flow_alerted_suricata"] == False)]
    
    tot_true_pos = tot_false_pos = tot_false_neg = tot_true_neg = 0

    tot_true_pos += len(df_tp)
    tot_false_pos += len(df_fp)
    tot_false_neg += len(df_fn)
    tot_true_neg += len(df_tn)

    return(tot_true_pos, tot_false_pos,tot_false_neg,tot_true_neg, False)
