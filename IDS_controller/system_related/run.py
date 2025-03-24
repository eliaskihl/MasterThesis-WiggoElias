# Run zeekctl
# Deploy workers
# https://dl.acm.org/doi/pdf/10.1145/2716260

### Relevant metrics:
## How to measure scalabilty?
# Look at cpu, memory and other system overhead when increasing the number of workers 
# test system stability by measuring over time and using heavy loads.
## How to measure Resiliance?
# (DoS) attack on system and see if the performance is affected
# Remove nodes during operation
## Measure system overhead
# CPU usage, memory usage for the controller
## Measure accuracy
# Accuracy of the IDS, just like in old framework
### Maybe not relevant:
## How to measure privacy
## How to measure self-configuration?
## How to measure interoperability?

import time
import subprocess
import psutil
import csv
import sys
import re
import os
from threading import Thread
import argparse
from dotenv import load_dotenv,find_dotenv

def revert_init_controller():
    # Comments out the required lines for Zeekctl to begin
    new_lines = []
    counter = 0
    filepath ="/usr/local/zeek/etc/node.cfg"
    with open(filepath, "r") as file:
        for line in file:
        # [zeek]
        # type=standalone
        # host=localhost
        # interface=eth0
            start = re.search(r"\s*#\[zeek\]\s*",line)
            if start or (counter >= 1 and counter < 4):
                line = line.split("#")
                new_lines.append(line[-1])
                counter += 1
            else:
                new_lines.append(line)
    with open(filepath,"w") as file:
        file.writelines(new_lines)

def init_controller():
    # Comments out the required lines for Zeekctl to begin
    new_lines = []
    counter = 0
    filepath ="/usr/local/zeek/etc/node.cfg"
    with open(filepath, "r") as file:
        for line in file:
        # [zeek]
        # type=standalone
        # host=localhost
        # interface=eth0
            start = re.search(r"\s*\[zeek\]\s*",line)
            if start or (counter >= 1 and counter < 4):
                new_lines.append("#" + line)
                counter += 1
            else:
                new_lines.append(line)
    with open(filepath,"w") as file:
        file.writelines(new_lines)
            
def deploy_worker(num, interface):
    #[worker-1]
    #type=worker
    #host=localhost
    #interface=eth
    new_lines = []
    filepath ="/usr/local/zeek/etc/node.cfg"
    for i in range(1,(num+1)):
        new_lines.append(f"[worker-{i}]\n")
        new_lines.append("type=worker\n")
        new_lines.append("host=localhost\n")
        new_lines.append(f"interface={interface}\n")
    with open(filepath,"a") as file:
        file.writelines(new_lines)       
        

def deploy_manager():
    #[manager]
    #type=manager
    #host=localhost
    new_lines = []
    filepath ="/usr/local/zeek/etc/node.cfg"
    new_lines.append("[manager]\n")
    new_lines.append("type=manager\n")
    new_lines.append("host=localhost\n")
    with open(filepath,"a") as file:
        file.writelines(new_lines)  

def deploy_proxy(num):
    #[proxy-1]
    #type=proxy
    #host=localhost
    new_lines = []
    filepath ="/usr/local/zeek/etc/node.cfg"
    for i in range(1,(num+1)):
        new_lines.append(f"[proxy-{i}]\n")
        new_lines.append("type=proxy\n")
        new_lines.append("host=localhost\n")
        
    with open(filepath,"a") as file:
        file.writelines(new_lines)    

def deploy_logger(num):
    #[logger-1]
    #type=logger
    #host=localhost
    new_lines = []
    filepath ="/usr/local/zeek/etc/node.cfg"
    for i in range(1,(num+1)):
        new_lines.append(f"[logger-{i}]\n")
        new_lines.append("type=logger\n")
        new_lines.append("host=localhost\n")
        
    with open(filepath,"a") as file:
        file.writelines(new_lines)

def remove(type,idx=0):
    new_lines = []
    counter = 0
    filepath ="/usr/local/zeek/etc/node.cfg"
    with open(filepath, "r") as file:
        for line in file:
            if type == "manager":
                if line == f"[{type}]\n" or (counter >= 1 and counter < 3):
                    counter += 1
                else:
                    new_lines.append(line)
            elif type == "worker":
                if line == f"[{type}-{idx}]\n" or (counter >= 1 and counter < 4):
                    counter += 1
                else:
                    new_lines.append(line)
            else:
                if line == f"[{type}-{idx}]\n" or (counter >= 1 and counter < 3):
                    counter += 1
                else:
                    new_lines.append(line)
    with open(filepath,"w") as file:
        file.writelines(new_lines)


def zeek_deploy():
    dotenv_path = find_dotenv()
    load_dotenv(dotenv_path)
    zeekctl_path = os.getenv("ZEEKCTL_PATH")
    subprocess.run(["sudo", zeekctl_path, "deploy"], capture_output=True)

def zeek_stop():
    dotenv_path = find_dotenv()
    load_dotenv(dotenv_path)
    zeekctl_path = os.getenv("ZEEKCTL_PATH")
    subprocess.run(["sudo", zeekctl_path, "stop"], capture_output=True)

def get_zeek_role(cmdline):
    
    match = re.search(r"-p\s+(logger-(\d+)|manager|proxy-(\d+)|worker-(\d+))",cmdline)
    return match.group(1) if match else "Unknown"

def log_performance(log_file,tcp_proc):
    
    # Logs CPU & memory usage of the IDS process every 5 seconds 
    with open(log_file, "w", newline="") as f:
        # Writes to csv
        writer = csv.writer(f)
        writer.writerow(["Time","Role", "CPU_Usage", "Memory_Usage"])  # CSV header
        psutil.cpu_percent(interval=10)
        while tcp_proc.poll() is None:
            # Find the process by name
           
            for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
                
                if "zeek" in proc.info["name"].lower():
                    try:
                        cmdline = " ".join(proc.cmdline())  # Get full command line
                    except psutil.AccessDenied:
                        cmdline = "Permission Denied"
                    #print("Role:",get_zeek_role(cmdline))
                    role = get_zeek_role(cmdline)
                    cpu_usage = proc.info["cpu_percent"]
                    rss_mem = proc.info["memory_info"].rss # Physical memory occupied by process
                    # Get the total system memory (in bytes)
                    tot_mem = psutil.virtual_memory().total
                    memory_percentage = (rss_mem / tot_mem) * 100

                    
                    writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"),role,cpu_usage, memory_percentage])
                    f.flush()

                    #print(proc.info["name"], ":", proc.info["cpu_percent"],":", memory_percentage, ":", proc.info["pid"])

            time.sleep(5)
            #psutil.process_iter.cache_clear()
    print("Logging complete")

def wait_for_zeekctl():
    time.sleep(5)

## Scalability test
# increase worker/proxy/logger size and throughput
def run(interface, speed, loop):
    dotenv_path = find_dotenv()
    load_dotenv(dotenv_path)
    zeekctl_path = os.getenv("ZEEKCTL_PATH")

    
    if not os.path.exists(f"./zeekctl/perf_files"):
        print("Directory not found, creating directory...")
        os.makedirs(f"./zeekctl/perf_files")
    filepath = f"./zeekctl/perf_files/ids_performance_log_{speed}.csv"
    # Start IDS as a subprocess
    print(f"Starting zeekctl...")
    if not os.path.exists(f"./tcp_replay/tmp/"):
        print("Directory not found, creating directory...")
        os.makedirs(f"./zeekctl/tmp/", exist_ok=True)
    with open(f"./zeekctl/tmp/temp.log", "w") as temp, \
        open(f"./zeekctl/tmp/err.log", "w") as err:   
        ids_proc = subprocess.Popen(["sudo", zeekctl_path, "deploy"], stdout=temp, stderr=err)
    # Wait for start of zeekctl
    wait_for_zeekctl()
    # Start tcp replay
    print("Starting tcp replay...")
    with open(f"./zeekctl/tmp/temp_tcpreplay.log", "w") as temp, \
        open(f"./zeekctl/tmp/err_tcpreplay.log", "w") as err:
        print("Current Working Directory:", os.getcwd())
        tcpreplay_proc = subprocess.Popen(["sudo", "tcpreplay", "-i", interface, f"--loop={loop}", f"--mbps={speed}", "./python/system_related/pcap/smallFlows.pcap"],stdout=temp, stderr=err)
    # Log performance in seperate thread while zeekctl is running and until tcpreplay is done
    monitor_thread = Thread(target=log_performance, args=(filepath, tcpreplay_proc))
    monitor_thread.start()
    time.sleep(1)
    # Wait / Terminate tcp replay
    print("Wait for TCP replay to finish")
    tcpreplay_proc.wait()
    time.sleep(1)
    print(f"Terminating tcpreplay..")
    tcpreplay_proc.terminate()
    time.sleep(2)
    # Wait / Terminate ids_proc
    print(f"Termating zeekctl..")
    ids_proc.terminate()
    time.sleep(1)
    print(f"Wait for zeekctl to finish")
    ids_proc.wait()
    end_ids = subprocess.Popen(["sudo", zeekctl_path, "stop"])
    end_ids.wait()
    end_ids.terminate()
    # End / join thread
    print("Terminating monitor thread")
    monitor_thread.join()

    exit(1)
    drop_rate, total_packets = extract_drop_rate_zeek()
    # Write drop rate to file
    with open(f"./zeekctl/perf_files_{pac_size}/drop_rate_{speed}.txt", "w") as f:
        f.write(str(drop_rate))
    with open(f"./zeekctl/perf_files_{pac_size}/total_packets_{speed}.txt", "w") as f:
        f.write(str(total_packets))

run("eth0",20,10)