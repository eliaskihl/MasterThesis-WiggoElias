import pandas as pd
import os
import pyshark
import csv
import xml.etree.ElementTree as ET
from datetime import datetime

xml_file = './smallFlows_output_labels.xml'
tree = ET.parse(xml_file)
root = tree.getroot()

timestamp_start = root.find('.//timestamp_start/timestamp_hr').text
timestamp_end = root.find('.//timestamp_end/timestamp_hr').text
print(timestamp_start)
print(timestamp_end)
cap = pyshark.FileCapture('./smallFlows_output.pcap')

with open('smallFlows_output.csv', 'w', newline='') as csvfile:
    fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp_start', 'timestamp_end']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()

    for pkt in cap:
        try:
            timestamp = pkt.sniff_time
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else ''
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else ''
            src_port = pkt.tcp.srcport if hasattr(pkt, 'tcp') else ''
            dst_port = pkt.tcp.dstport if hasattr(pkt, 'tcp') else ''

            writer.writerow({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'timestamp_start': timestamp_start,
                'timestamp_end': timestamp_end
            })
        except AttributeError:
            continue
            
df = pd.read_csv('smallFlows_output.csv')

df['timestamp'] = pd.to_datetime(df['timestamp'], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')
df['timestamp_start'] = pd.to_datetime(df['timestamp_start'], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')
df['timestamp_end'] = pd.to_datetime(df['timestamp_end'], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')

df['timestamp_start'] = df['timestamp_start'] + pd.Timedelta(hours=1)
df['timestamp_end'] = df['timestamp_end'] + pd.Timedelta(hours=1)

df['flow_alerted'] = df.apply(
    lambda row: 1 if row['timestamp_start'] <= row['timestamp'] <= row['timestamp_end'] else 0,
    axis=1
)

df.to_csv('ground_truth.csv', index=False)