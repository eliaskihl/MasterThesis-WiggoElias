import argparse
from collections import defaultdict
import time
import subprocess
import psutil
import csv
import re
from datetime import datetime
import glob
import os
import gzip
from threading import Thread
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from python.system_related.run_throughput import check_tcpreplay_throughput, restart_interface


def revert_init_controller():
    # Comments the required lines for Zeekctl to begin
    
    new_lines = []
    counter = 0
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
    with open(filepath, "r") as file:
        for line in file:
        # [zeek]
        # type=standalone
        # host=localhost
        # interface=eth0
            start = re.search(r"\s*#\[zeek\]\s*",line)
            if start or (counter >= 1 and counter < 4):
                
                text = line.replace('#','')
                new_lines.append(text)
                counter += 1
            else:
                new_lines.append(line)
    with open(filepath,"w") as file:
        file.writelines(new_lines)

def init_controller():
    # Comments out the required lines for Zeekctl to begin
    new_lines = []
    counter = 0
    print("Current Working Directory:", os.getcwd())
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
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
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
   
    new_lines.append(f"[worker-{num}]\n")
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
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
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
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
    
    new_lines.append(f"[proxy-{num}]\n")
    new_lines.append("type=proxy\n")
    new_lines.append("host=localhost\n")
        
    with open(filepath,"a") as file:
        file.writelines(new_lines)    

def deploy_logger(num):
    #[logger-1]
    #type=logger
    #host=localhost
    new_lines = []
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
    
    new_lines.append(f"[logger-{num}]\n")
    new_lines.append("type=logger\n")
    new_lines.append("host=localhost\n")
        
    with open(filepath,"a") as file:
        file.writelines(new_lines)

def remove_all():
    new_lines = []
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
    passed = False
    with open(filepath, "r") as file:
        for line in file:
            if not passed:
                new_lines.append(line)
            elif passed:
                pass
            if "remove the [zeek] node above." in line:
                passed = True
    with open(filepath,"w") as file:
        file.writelines(new_lines)

def remove(type,idx=0):
    new_lines = []
    counter = 0
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
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

def check_all_worker_interfaces(interface):
    new_lines = []
    filepath ="./../../python/ids_configuration/zeek/config/zeek/node.cfg"
    # interface=veth_host
    with open(filepath,"r") as file:
        for line in file:
            if "interface" in line and not  f"{interface}" in line and '#' not in line:
                new_lines.append(f"interface={interface}\n")
            else:
                new_lines.append(line)
    with open(filepath,"w") as file:
        file.writelines(new_lines)   

def deploy(interface,workers=1,proxys=1,managers=1,loggers=1):
    
    for i in range(workers):
        deploy_worker((i+1),interface)
    for i in range(loggers):
        deploy_logger((i+1))
    for i in range(proxys):
        deploy_proxy((i+1))
    for i in range(managers):
        deploy_manager()

def get_zeek_role(cmdline):  
    match = re.search(r"-p\s+(logger-(\d+)|manager|proxy-(\d+)|worker-(\d+))",cmdline)
    return match.group(1) if match else "Unknown"


def extract_drop_rate_zeekctl():
    
    today = datetime.today().strftime("%Y-%m-%d")
    print(today)
    stats_path = f"./../../python/ids_configuration/zeek/logs/{str(today)}/stats.*.log.gz"
    file_paths = glob.glob(stats_path)
    print(file_paths)
    
    roles = {}
    for path in file_paths:
        print(path)
        subprocess.run(["sudo", "gzip", "-d", path])
        with open(path.replace(".gz",""), "r") as file:
            for line in file:
                
                if line.startswith("#") or not line.strip():
                    continue  # Skip metadata lines
                # Fields are seperated by tabs
                fields = line.strip().split("\t")  # Fields are tab-separated
                role = fields[1]
                pkts_proc = 0 if int(fields[3]) == "-" else int(fields[3])
                pkts_dropped = 0 if fields[5] == "-" else int(fields[5])
                # Update roles dict with Role: (Processed packets, Dropped packets)
                print("role",role,"tot",pkts_proc,"drop",pkts_dropped)
                
                # If the role already exists in the dictionary, append (sum) the values
                if role in roles:
                    existing_pkts_proc, existing_pkts_dropped = roles[role]
                    roles[role] = (existing_pkts_proc + pkts_proc, existing_pkts_dropped + pkts_dropped)
                else:
                    roles[role] = (pkts_proc, pkts_dropped)
    
        # If there is more than one path only the last one will be used?
    return roles 

def remove_logs():
    today = datetime.today().strftime("%Y-%m-%d")
    # Remove all logs
    directory = f"./../../python/ids_configuration/zeek/logs/{str(today)}/*"  
    # Get all files in the directory
    subprocess.run(f"sudo rm -rf {directory}", shell=True, check=True)
        

def log_performance(log_file,tcp_proc):
    
    # Logs CPU & memory usage of the IDS process every 5 seconds 
    with open(log_file, "w", newline="") as f:
        # Writes to csv
        writer = csv.writer(f)
        writer.writerow(["Time","Role", "CPU_Usage", "Memory_Usage", "Upload_Speed", "Download_Speed"])  # CSV header
        
        # Initate a baseline for cpu precentage
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # Skip processes that may terminate or be inaccessible
        
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

            time.sleep(1) 
            #psutil.process_iter.cache_clear()
    print("Logging complete")

def wait_for_zeekctl():
    time.sleep(20)

def extract_tcpreplay_drop_rate(speed,dict_for_drop_rates):
    # Recorded total packets according to TCPreplay
    tcpreplay_total_packets = 0
    log = "./zeekctl/tmp/temp_tcpreplay.log"
    with open(log, "r") as file:
        for line in file:
            match = re.search(r"Successful packets:\s*(\d+)", line)
            if match:
                tcpreplay_total_packets = int(match.group(1))   
                
    # Recorded total packets by zeekctl
    for role, packets_tuple in dict_for_drop_rates.items():
        zeek_total_packets,_ = packets_tuple 
        tcpreplay_drop_rate = 0 if zeek_total_packets <= 0 or zeek_total_packets >= tcpreplay_total_packets else (1-zeek_total_packets/tcpreplay_total_packets)*100 
        print("Actual drop rate:",tcpreplay_drop_rate)
        with open(f"./zeekctl/perf_files/tcpreplay_drop_rate_{role}_{speed}.txt", "w") as f: 
                f.write(str(tcpreplay_drop_rate)) # Precentage



def run(interface, speed, loop):
    tries = 0
    while True:
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
            command = [
                "sudo",
                "docker",
                "exec",
                "zeek-container",
                "bash",
                "-c",
                f"cd logs && zeekctl deploy"
            ]
            # command = ["sudo", zeekctl_path, "deploy"]
            ids_proc = subprocess.Popen(command, stdout=temp, stderr=err)
        # Wait for start of zeekctl
        wait_for_zeekctl()
        # Start tcp replay
        print("Starting tcp replay...")
        with open(f"./zeekctl/tmp/temp_tcpreplay.log", "w") as temp, \
            open(f"./zeekctl/tmp/err_tcpreplay.log", "w") as err:
            
            command = [
            "sudo",
            "docker", 
            "exec", 
            "zeek-container",
            "tcpreplay",
            "-i", interface,
            f"--loop={loop}",
            f"--mbps={speed}",
            "/pcap/smallFlows.pcap"
            ]
            # command = ["sudo", "tcpreplay", "-P", "--stats=1", "-i", interface, f"--loop={loop}", f"--mbps={speed}", "./python/system_related/pcap/smallFlows.pcap"]
            tcpreplay_proc = subprocess.Popen(command,stdout=temp, stderr=err)
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
        time.sleep(1)
        print(f"Wait for zeekctl to finish")
        ids_proc.wait()
        command = [
                "sudo",
                "docker",
                "exec",
                "zeek-container",
                "bash",
                "-c",
                f"cd logs && zeekctl stop"
        ]
        # command = ["sudo", zeekctl_path, "stop"]
        subprocess.Popen(command)

        # End / join thread
        print("Terminating monitor thread")
        monitor_thread.join()
        time.sleep(2)
        if check_tcpreplay_throughput("zeekctl",speed): # If not a match then restart 
            
            # Wait for values to be updated
            time.sleep(10)
            # Two methods of extracting the drop rate, which one is the best?
            update_and_clean_docker_logs()
            dict_for_drop_rates = extract_drop_rate_zeekctl() # Return a dictionary with all roles and their respective total packets and dropped packet as a tuple 
            # Write drop rate to file
            total_packets_var = 0
            for role, packets_tuple in dict_for_drop_rates.items():
                total_packets,dropped_packets = packets_tuple 
                total_packets_var += total_packets
                drop_rate = 0 if total_packets <= 0 else (dropped_packets/total_packets)*100
                with open(f"./zeekctl/perf_files/drop_rate_{role}_{speed}.txt", "w") as f:
                    f.write(str(drop_rate))
                with open(f"./zeekctl/perf_files/total_packets_{role}_{speed}.txt", "w") as f:
                    f.write(str(total_packets))
            # According to tcp replay the drop rate is higher than zeekctl has recorded
            extract_tcpreplay_drop_rate(speed,dict_for_drop_rates)
            break
        else:
            tries+=1
            print("Number of tries:",tries)
            update_and_clean_docker_logs()
            remove_logs()
            restart_interface(interface.replace("_host",'')) 
        
def check_if_same_interface(): # TODO: Check that the same interface is used in "run" as defined in workers
    pass

def wait_for_start(): # TODO: Based on the scale of the network should wait that time
    pass
    

def update_and_clean_docker_logs():
    # Local directory to store logs from the Docker container
    local_config_file = "./../../python/ids_configuration/zeek/"
    # Directory inside the Docker container where Zeek logs are stored
    container_config_path = "/usr/local/zeek/logs/"
    # Today
    today = datetime.today().strftime("%Y-%m-%d")
    # Ensure the local directory exists, create it if not
    if not os.path.exists(local_config_file):
        os.makedirs(local_config_file)
    # Run the Docker command to copy logs from the container to the local system
    try:
        subprocess.run(["docker", "cp", f"zeek-container:{container_config_path}", local_config_file], check=True)
        #print(f"Logs successfully copied from container 'zeek-container' to {local_config_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to copy logs from the container. Details: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    
    ### Clean docker logs
    target_path = f"/usr/local/zeek/logs/{str(today)}"
    try:
        # The `rm -rf` command to clean the target directory
        command = f"rm -rf {target_path}/*"

        result = subprocess.run(
            ["sudo","docker", "exec", "zeek-container", "sh", "-c", command],
            check=True,
            # text=True,
            # capture_output=True  # Captures both stdout and stderr
        )
        
        # # If the command was successful, print the output
        # print("Command succeeded!")
        # print("Output:\n", result.stdout)  # The standard output of the command
        # print("Error (if any):\n", result.stderr)  # The error output of the command (if any)

        print(f"Cleaned contents of '{target_path}' inside container zeek-container'.")

    except subprocess.CalledProcessError as e:
        print(f"Failed to clean directory in container: {e}")

def open_maybe_gzipped(path, mode='rt'):
    if path.endswith('.gz'):
        return gzip.open(path, mode)
    return open(path, mode)

def measure_latency():
    today = datetime.today().strftime("%Y-%m-%d")
    stats_path = f"./../../python/ids_configuration/zeek/logs/{str(today)}/cluster.*.log*" 
    file_paths = glob.glob(stats_path)
    print(file_paths)
    roles = {}
    for path in file_paths:
        print(path)
        # subprocess.run(["sudo", "gzip", "-d", path])
        temp_dict = {}
        try:
            with open_maybe_gzipped(path) as file:
                for line in file:
                # 1743092612.165135	logger-1	got hello from manager (72c0fbec-a4fc-5545-8e6d-2b244618b4fa)
                # 1743092612.165017	manager	got hello from logger-1 (19dd8eaf-8fba-5797-aead-6263755e69cc)

                    if line.startswith("#") or not line.strip():
                        continue  # Skip metadata lines
                    # Fields are seperated by tabs
                    fields = line.strip().split("\t")  # Fields are tab-separated

                    time = fields[0]
                    role = fields[1]
                    message = fields[2]
                    if "from"  in message:
                            
                        # print("0",message)
                        target_role = message.split("from")[-1]
                        # print("1",target_role)
                        target_role = target_role.split(" ")[1]
                        # print("2",target_role)
                        
                        temp_dict[(role,target_role)] = time
        
        except Exception as e:
            print(f"Error reading {path}: {e}")

                
            
        #Find the pairs in the dict and take the delta time
        banned = []
        
        for outer_tuple,outer_time in temp_dict.items():
            
            start = float(outer_time)
            if outer_tuple in banned: # Skip 
                continue

            for inner_tuple,inner_time in temp_dict.items():
                
                end = float(inner_time)
                # print("rev:",keys[::-1])
                if inner_tuple == outer_tuple[::-1]: # Found match
                
                    if end > start:
                        roles[(outer_tuple)] = end-start 
                    else:
                        roles[(outer_tuple)] = start-end 
                    banned.append((inner_tuple)) # Ban the target
                    break
        
        print(roles)
        return roles # TODO: If this loop is greater than 1 iteration than this will fail
             


def count_crashed_nodes():
    today = datetime.today().strftime("%Y-%m-%d")
    
    # Supports both zipped and unzipped files
    stats_paths = glob.glob(f"./../../python/ids_configuration/zeek/logs/{today}/cluster.*.log*")
    
    events = []
    results = {}
    start_role = None
    for path in stats_paths:
        print(f"Reading from: {path}")
        
        try:
            with open_maybe_gzipped(path) as file:
                for line in file:
                    if "listening on" in line:
                        # Find the first role
                        fields = line.strip().split("\t")
                        start_role = fields[1]
                        results[start_role] = 0
                    if line.startswith("#close"):
                        # First node terminated successfully
                        results[start_role] += 1 
                    if line.startswith("#") or not line.strip():
                        continue  # Skip metadata or empty lines
                    
                    if "node down" in line:
                        fields = line.strip().split("\t")
                        if len(fields) < 3:
                            continue  # Avoid index errors

                        time = float(fields[0])
                        message = fields[2]

                        if "node down:" in message:
                            target_node = message.split("node down: ")[-1].strip()
                            events.append((time, target_node))

        except Exception as e:
            print(f"Error reading {path}: {e}")

    # Sort events by time
    events.sort()
    
    THRESHOLD = 1.0
    counter = 1 # Every "role" in the list will have been shutdown atleast once
    
    for x,(time, node) in enumerate(events):
        if node != events[x-1][-1] and x != 0: # When the nodes are not the same and not the first we need to update results

            results[events[x][-1]] = 1  # Give start value of 1 (update if we come back)
            results[events[x-1][-1]] = counter  # Add old entry to results (have been fully counted)
            
            counter = 1 # Reset counter
            
        elif node == events[x-1][-1]:  # Same node as previous, we must calculate the time difference
            delta = time - events[x-1][0] # Delta time 
            if delta > THRESHOLD: # Compare to Threshold
                counter += 1

    print(results)
    return results     
    # TODO: Missing the logger



def run_controller(interface, first=10, last=60, step=10, loop=10, worker=1,manager=1,proxy=1,logger=1):
    start = time.time()
    
    
    first = int(first)
    last = int(last)
    step = int(step)
    loop = int(loop)
    worker = int(worker)
    manager = int(manager)
    proxy = int(proxy)
    logger = int(logger)
    
    
    update_and_clean_docker_logs()
    remove_logs() 
    restart_interface(interface)
    host_interface = interface+"_host" # Restart creates new interface with name "interface_host"
    remove_all()
    revert_init_controller()
    init_controller()
    deploy(host_interface,worker,proxy,manager,logger)
    check_all_worker_interfaces(host_interface)
    

    for i in range(first,last,step):
        print("Speed:",i)
        run(host_interface,i,loop)
        crashed_nodes = count_crashed_nodes()
        latencies = measure_latency()

        with open(f"./zeekctl/perf_files/count_crashed_{i}.txt", "w") as f: 
                f.write(str(crashed_nodes)) 
        with open(f"./zeekctl/perf_files/latencies_{i}.txt", "w") as f: 
                f.write(str(latencies)) 
        remove_logs() 
    
    # Cleanup
    remove_all()
    revert_init_controller()
    
    remove_logs()     
    # visualize()
    end = time.time()
    print("Runtime:",end-start)
    
    








                