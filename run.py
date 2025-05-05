from python.security_related.suricata.run_suricata import run_suricata_dataset, run_suricata_traffic_generator
from python.security_related.snort.run_snort import run_snort_dataset, run_snort_traffic_generator
from python.security_related.zeek.run_zeek import run_zeek_dataset, run_zeek_traffic_generator
from python.system_related.run_latency import run_latency
from python.system_related.run_throughput import run_throughput
from python.system_related.run_par import run_parallel
from python.system_related.vis_all import visualize
from IDS_controller.system_related.run import run_controller
from IDS_controller.system_related.vis import visualize_controller

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
    'BOT-IOT': ['Theft/Data_Exfiltration/Data_Exfiltration.pcap'],
    'TII-SSRC-23': ['malicious/bruteforce/bruteforce_http.pcap'],
    'UNSW-NB15': ['pcaps_22-1-2015/pcaps_22-1-2015.pcap'],
    'CIC-IDS2017': ['Tuesday-WorkingHours_small.pcap']
}

# Traffic generator and attack combinations
TRAFFIC_GENERATORS = {
    'ID2T': ['EternalBlueExploit', 'PortscanAttack']
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
                            "error": "No alerts or no result"
                        })

                except Exception as e:
                    results.append({
                        "tool": tool,
                        "dataset": dataset,
                        "pcap": pcap,
                        "error": str(e)
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
                            "error": "No alerts or no result"
                        })

                except Exception as e:
                    results.append({
                        "tool": tool,
                        "traffic_generator": traffic_generator,
                        "attack": attack,
                        "error": str(e)
                    })

# ----------------- Argument Parsing --------------------
parser = argparse.ArgumentParser(description="Run specified security tools from the root directory")
parser.add_argument("--tool", required=True, help="Name of the tool to run (e.g., suricata, snort, zeek)")
parser.add_argument("--dataset", help="Name of the dataset to run (optional for single runs)")
parser.add_argument("-i",help="interface")
parser.add_argument("-b",help="begin")
parser.add_argument("-e",help="end")
parser.add_argument("-s",help="step")
parser.add_argument("-speed",help="Throughput for latency eval")
parser.add_argument("-loop",help="How many time should tcpreplay replay the traffic, will create a generate a specific load.")
parser.add_argument("-workers",help="Number of workers")
parser.add_argument("-manager",help="Number of managers")
parser.add_argument("-proxy",help="Number of proxies")
parser.add_argument("-logger",help="Number of loggers")
parser.add_argument("--pcap", help="Path to the pcap file (optional for single runs)")
parser.add_argument("--traffic_generator", help="Name of the traffic generator (optional for single runs)")
parser.add_argument("--attack", help="Attack to simulate (optional for single runs)")
parser.add_argument("--type",help="Choose to viszualize the latency or throughput files, (can be latency or throughput)")
parser.add_argument("args", nargs=argparse.REMAINDER, help="Additional arguments for the script")

args = parser.parse_args()
tool = args.tool
if tool in ["latency", "parallel", "throughput", "controller"]:
    print(args.tool)
    print(args.i)
    print(args.speed)
    print(args.loop)
    print(args.e)
    print(args.b)
    print(args.s)
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
                visualize(args.type)
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
                "error": "No alerts or no result"
            })

        df = pd.DataFrame(results)
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
        df.to_csv('run_results.csv', index=False)
        print("Results saved to run_results.csv")
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
                "error": "No alerts or no result"
            })

        df = pd.DataFrame(results)
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
        df.to_csv('run_results.csv', index=False)
        print("Results saved to run_results.csv")
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
    df.to_csv('run_results.csv', index=False)
    print("Results saved to run_results.csv")
    exit(0)

# Special case: run all traffic generators
if args.tool == "traffic_generators":
    results = []
    run_traffic_generators(results)
    df = pd.DataFrame(results)
    if 'tool' in df.columns:
        cols = ['tool'] + [col for col in df.columns if col != 'tool']
        df = df[cols]
    df.to_csv('run_results.csv', index=False)
    print("Results saved to run_results.csv")
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
    df.to_csv('run_results.csv', index=False)
    print("Results saved to run_results.csv")
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
