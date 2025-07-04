from python.security_related.suricata.run_suricata import run_suricata_dataset, run_suricata_traffic_generator
from python.security_related.snort.run_snort import run_snort_dataset, run_snort_traffic_generator
from python.security_related.zeek.run_zeek import run_zeek_dataset, run_zeek_traffic_generator
from python.system_related.run_latency import run_latency
from python.system_related.run_throughput import run_throughput
from python.system_related.run_par import run_parallel
from python.system_related.vis_all import visualize
from IDS_controller.system_related.run import run_controller
from IDS_controller.system_related.vis import visualize_controller
from table_generation import table_generation

import subprocess
import argparse
import os
import sys
import pandas as pd
from pathlib import Path
import contextlib

@contextlib.contextmanager
def change_dir(target_dir):
    prev_dir = os.getcwd()
    os.chdir(target_dir)
    try:
        yield
    finally:
        os.chdir(prev_dir)

if not os.path.exists(f"./tables/"):
            print("Directory not found, creating directory...")
            os.makedirs(f"./tables/", exist_ok=True)
# Mapping of tool names to their respective directories and scripts
TOOLS = {
    "suricata": {"dir": "python/security_related/suricata", "script": "run_suricata.py"},
    "snort": {"dir": "python/security_related/snort", "script": "run_snort.py"},
    "zeek": {"dir": "python/security_related/zeek", "script": "run_zeek.py"},
    "throughput": {"dir": "python/system_related", "script": "run_throughput.py"},
    "parallel": {"dir": "python/system_related", "script": "run_par.py"},
    "latency": {"dir": "python/system_related", "script": "run_latency.py"},
    "visualize": {"dir": "python/system_related", "script": "vis_all.py"},
    "controller": {"dir": "IDS_controller/system_related", "script": "run.py"},
    "visualize_controller": {"dir": "IDS_controller/system_related", "script": "vis.py"},
    "table": {"dir": ".", "script": "table_generation.py"},
}

# Dataset and pcap combinations
DATASETS = {
    'BOT-IOT': ['Theft/Data_Exfiltration/Data_Exfiltration.pcap', 'Theft/Keylogging/keylogging.pcap', 'DoS/DoS_HTTP/DoS_HTTP.pcap', 'Scan/Service/Service.pcap'],
    'TII-SSRC-23': [
        'benign/audio/audio.pcap',
        'benign/background/background.pcap',
        'benign/text/text.pcap',
        'benign/video/http.pcap',
        'benign/video/rtp.pcap',
        'benign/video/udp.pcap',
        'malicious/bruteforce/bruteforce_dns.pcap',
        'malicious/bruteforce/bruteforce_ftp.pcap',
        'malicious/bruteforce/bruteforce_http.pcap',
        'malicious/bruteforce/bruteforce_ssh.pcap',
        'malicious/bruteforce/bruteforce_telnet.pcap',
        'malicious/dos/ack_tcp_dos.pcap',
        'malicious/dos/cwr_tcp_dos.pcap',
        'malicious/dos/ecn_tcp_dos.pcap',
        'malicious/dos/fin_tcp_dos.pcap',
        'malicious/dos/http_dos.pcap',
        'malicious/dos/icmp_dos.pcap',
        'malicious/dos/mac_dos.pcap',
        'malicious/dos/psh_tcp_dos.pcap',
        'malicious/dos/rst_tcp_dos.pcap',
        'malicious/dos/syn_tcp_dos.pcap',
        'malicious/dos/udp_dos.pcap',
        'malicious/dos/urg_tcp_dos.pcap',
        'malicious/information-gathering/information_gathering.pcap',
        'malicious/mirai-botnet/mirai_ddos_ack.pcap',
        'malicious/mirai-botnet/mirai_ddos_dns.pcap',
        'malicious/mirai-botnet/mirai_ddos_greeth.pcap',
        'malicious/mirai-botnet/mirai_ddos_greip.pcap',
        'malicious/mirai-botnet/mirai_ddos_http.pcap',
        'malicious/mirai-botnet/mirai_ddos_syn.pcap',
        'malicious/mirai-botnet/mirai_ddos_udp_udpplain.pcap',
        'malicious/mirai-botnet/mirai_scan_bruteforce.pcap'
    ],
    'UNSW-NB15': ['pcaps_22-1-2015/pcaps_22-1-2015.pcap'],
    'CIC-IDS2017': ['Tuesday-WorkingHours_small.pcap']
}

# Traffic generator and attack combinations
TRAFFIC_GENERATORS = {
    'ID2T': ['EternalBlueExploit', 'FTPWinaXeExploit', 'JoomlaRegPrivExploit', 'MS17ScanAttack', 'MemcrashedSpooferAttack','P2PBotnet',
             'PortscanAttack', 'SMBLorisAttack', 'SMBScanAttack', 'SQLiAttack','SalityBotnet']
}


def run_datasets(results):
    for tool, tool_info in TOOLS.items():
        if tool not in ['snort', 'suricata', 'zeek']:
            continue

        for dataset, pcaps in DATASETS.items():
            for pcap in pcaps:
                try:
                    print(f"Running: {tool} | Dataset: {dataset} | PCAP: {pcap}")
                    with change_dir(tool_info["dir"]):
                        if tool == "suricata":
                            result = run_suricata_dataset(dataset, pcap)
                        elif tool == "snort":
                            result = run_snort_dataset(dataset, pcap)
                        elif tool == "zeek":
                            result = run_zeek_dataset(dataset, pcap)

                    if result:
                        result["tool"] = tool
                        results.append(result)
                    else:
                        results.append({
                            "tool": tool,
                            "dataset": dataset,
                            "pcap": pcap,
                        })

                except Exception as e:
                    results.append({
                        "tool": tool,
                        "dataset": dataset,
                        "pcap": pcap,
                    })

def run_traffic_generators(results):
    for tool, tool_info in TOOLS.items():
        if tool not in ['snort', 'suricata', 'zeek']:
            continue

        for traffic_generator, attacks in TRAFFIC_GENERATORS.items():
            for attack in attacks:
                try:
                    print(f"Running: {tool} | Traffic-Generator: {traffic_generator} | Attack: {attack}")
                    with change_dir(tool_info["dir"]):
                        if tool == "suricata":
                            result = run_suricata_traffic_generator(traffic_generator, attack)
                        elif tool == "snort":
                            result = run_snort_traffic_generator(traffic_generator, attack)
                        elif tool == "zeek":
                            result = run_zeek_traffic_generator(traffic_generator, attack)

                    if result:
                        result["tool"] = tool
                        result["traffic_generator"] = traffic_generator
                        result["attack"] = attack
                        results.append(result)
                    else:
                        results.append({
                            "tool": tool,
                            "traffic_generator": traffic_generator,
                            "attack": attack,
                        })

                except Exception as e:
                    results.append({
                        "tool": tool,
                        "traffic_generator": traffic_generator,
                        "attack": attack,
                    })

# ----------------- Argument Parsing --------------------
parser = argparse.ArgumentParser(description="Run specified security tools from the root directory")
parser.add_argument("-tool", required=True, help="Name of the tool to run (e.g., suricata, snort, zeek)")
parser.add_argument("-dataset", help="Name of the dataset to run (optional for single runs)")
parser.add_argument("-i",help="interface")
parser.add_argument("-b",help="begin")
parser.add_argument("-e",help="end")
parser.add_argument("-s",help="step")
parser.add_argument("-speed",help="Throughput for latency eval")
parser.add_argument("-loop",help="How many time should tcpreplay replay the traffic, will create a generate a specific load.")
parser.add_argument("-worker",help="Number of workers")
parser.add_argument("-manager",help="Number of managers")
parser.add_argument("-proxy",help="Number of proxies")
parser.add_argument("-logger",help="Number of loggers")
parser.add_argument("-pcap", help="Path to the pcap file (optional for single runs)")
parser.add_argument("-traffic_generator", help="Name of the traffic generator (optional for single runs)")
parser.add_argument("-attack", help="Attack to simulate (optional for single runs)")
parser.add_argument("-type",help="Choose to viszualize the latency or throughput files, (can be latency or throughput)")
parser.add_argument("-run_all",help="Run all files before creating the table")
parser.add_argument("-num_cores",help="Run all files before creating the table")
parser.add_argument("args", nargs=argparse.REMAINDER, help="Additional arguments for the script")

args = parser.parse_args()
tool = args.tool
if tool == "table":
    
    if "run_all" in args.args:
        table_generation(True)
    else:
        table_generation(False)

if tool in ["latency", "parallel", "throughput", "controller"]:
    
    if args.i:
        try:
            with change_dir(TOOLS[tool]["dir"]):
                if tool == "latency":
                    
                    run_latency(args.i, args.speed, args.loop)
                elif tool == "throughput":
                    
                    run_throughput(args.i, args.b, args.e, args.s, args.loop)
                elif tool == "parallel":
                    
                    run_parallel(args.i, args.b, args.e, args.s, args.loop)
                elif tool == "controller":

                    run_controller(args.i, args.b, args.e, args.s, args.loop, args.worker, args.manager, args.proxy, args.logger)
                
        except Exception as e:
            print(f"Error while running system evalution: {e}")
        exit(0)
    else:
        raise Exception("Missing interface arguemnt")
if tool in ["visualize", "visualize_controller"]:
    try:
        with change_dir(TOOLS[tool]["dir"]):
            if tool == "visualize":
                visualize(args.type, args.num_cores)
            elif tool == "visualize_controller":
                visualize_controller()
    except Exception as e:
            print(f"Error while running system evalution visuialization: {e}")
# Handle specific dataset + pcap
if args.dataset and args.pcap:
    tool = args.tool
    if tool not in ['suricata', 'snort', 'zeek']:
        print(f"Error: Tool '{tool}' does not support dataset mode")
        exit(1)

    try:
        with change_dir(TOOLS[tool]['dir']):
            if tool == "suricata":
                result = run_suricata_dataset(args.dataset, args.pcap)
            elif tool == "snort":
                result = run_snort_dataset(args.dataset, args.pcap)
            elif tool == "zeek":
                result = run_zeek_dataset(args.dataset, args.pcap)

        results = []
        if result:
            result["tool"] = tool
            result["dataset"] = args.dataset
            result["pcap"] = args.pcap
            results.append(result)
        else:
            results.append({
                "tool": tool,
                "dataset": args.dataset,
                "pcap": args.pcap,
            })

        df = pd.DataFrame(results)
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
        df.to_csv('./tables/classification_evaluation/classifications.csv', index=False)
        print("Results saved to classifications.csv")
    except Exception as e:
        print(f"Error while running single dataset: {e}")
    exit(0)

# Handle specific traffic generator + attack
if args.traffic_generator and args.attack:
    tool = args.tool
    if tool not in ['suricata', 'snort', 'zeek']:
        print(f"Error: Tool '{tool}' does not support traffic generation mode")
        exit(1)

    try:
        with change_dir(TOOLS[tool]['dir']):
            if tool == "suricata":
                result = run_suricata_traffic_generator(args.traffic_generator, args.attack)
            elif tool == "snort":
                result = run_snort_traffic_generator(args.traffic_generator, args.attack)
            elif tool == "zeek":
                result = run_zeek_traffic_generator(args.traffic_generator, args.attack)

        results = []
        if result:
            result["tool"] = tool
            result["traffic_generator"] = args.traffic_generator
            result["attack"] = args.attack
            results.append(result)
        else:
            results.append({
                "tool": tool,
                "traffic_generator": args.traffic_generator,
                "attack": args.attack,
            })

        df = pd.DataFrame(results)
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
        df.to_csv('./tables/classification_evaluation/classifications.csv', index=False)
        print("Results saved to classifications.csv")
    except Exception as e:
        print(f"Error while running single attack: {e}")
    exit(0)

# Special case: run all datasets
if args.tool == "datasets":
    results = []
    run_datasets(results)
    df = pd.DataFrame(results)
    if 'tool' in df.columns:
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
    df.to_csv('./tables/classification_evaluation/classifications.csv', index=False)
    print("Results saved to classifications.csv")
    exit(0)

# Special case: run all traffic generators
if args.tool == "traffic_generators":
    results = []
    run_traffic_generators(results)
    df = pd.DataFrame(results)
    if 'tool' in df.columns:
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
    df.to_csv('./tables/classification_evaluation/classifications.csv', index=False)
    print("Results saved to classifications.csv")
    exit(0)

# Run both datasets and traffic generators
if args.tool == "datasets_traffic_generators":
    results = []
    run_datasets(results)
    run_traffic_generators(results)
    df = pd.DataFrame(results)
    if 'tool' in df.columns:
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
    df.to_csv('./tables/classification_evaluation/classifications.csv', index=False)
    print("Results saved to classifications.csv")
    exit(0)

# Fallback: direct script dispatch
if args.tool not in TOOLS:
    print(f"Error: Unknown tool '{args.tool}'. Available tools: {', '.join(TOOLS.keys())}")
    exit(1)

tool_info = TOOLS[args.tool]
nested_dir = tool_info["dir"]
script = tool_info["script"]

command = ["python", script] + args.args
subprocess.run(command, cwd=nested_dir)
