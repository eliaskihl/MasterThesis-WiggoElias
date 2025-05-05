import time
import subprocess
from threading import Thread
import os
import re 
import argparse
from python.system_related.run_throughput import (
    log_performance, 
    extract_drop_rate_suricata, 
    extract_drop_rate_snort, 
    extract_drop_rate_zeek, 
    restart_interface
    )

def check_tcpreplay_throughput(interface, target_speed): #TODO:
    
    threshold_percentage = 5  
    lower_bound = target_speed * (1 - threshold_percentage / 100)
    upper_bound = target_speed * (1 + threshold_percentage / 100)
    log = f"./dir_{interface}/tmp/temp_tcpreplay.log"
    with open(log, "r") as file:
        for line in file:
            #Rated: 4999998.1 Bps, 39.99 Mbps, 7736.63 pps
            match = re.search(r"Rated:\s*([\d\.]+)\s*Bps,\s*([\d\.]+)\s*Mbps,\s*([\d\.]+)\s*pps", line)
            if match:
                tcpreplay_speed = float(match.group(2))  
                break
    if lower_bound <= tcpreplay_speed <= upper_bound:
        print("OK throughput")
        return True # Throughput is okay
        
    else:
        print("Not OK throughput")
        return False
def wait_for_all():
    while True:
        # Open and read each log file
        with open(f"./suricata/tmp/temp.log", 'r') as suricata_file, \
             open(f"./zeek/tmp/err.log", 'r') as zeek_file, \
             open(f"./snort/tmp/temp.log", 'r') as snort_file:
            
            suricata_status = "Engine started" in suricata_file.read()
            zeek_status = "listening on" in zeek_file.read()
            snort_status = "ntp:" in snort_file.read()
            
            # If all conditions are met, exit the loop
            if suricata_status and zeek_status and snort_status:
                break
        
        time.sleep(2)  # Sleep before checking again

def tcpreplay_execution(name,loop,speed,interface,proc):
    if not os.path.exists(f"./dir_{interface}/tmp/"):
            print("Directory not found, creating directory...")
            os.makedirs(f"./dir_{interface}/tmp/")
    with open(f"./dir_{interface}/tmp/temp_tcpreplay.log", "w") as temp, \
        open(f"./dir_{interface}/tmp/err_tcpreplay.log", "w") as err:
        try:
            cmd = [
                "sudo",
                "docker", 
                "exec", 
                f"{name}-container",
                "tcpreplay",
                "-i", interface,
                f"--loop={loop}",
                f"--mbps={speed}",
                "/pcap/smallFlows.pcap"
            ]
            proc[interface] = subprocess.Popen(cmd,stdout=temp, stderr=err)
            
        except Exception as e:
            print(f"Error starting tcpreplay on {interface}: {e}")
            proc[interface] = None
    
def run(loop, speed, interfaces, recursion_count=0, max_recursions=5):
    
    if recursion_count >= max_recursions: # Stop recursion after 5 calls
        print(f"Maximum recursion limit reached ({max_recursions}), failed to reach throughput: {speed}.")
        return  


    print("LOOP:",loop, " | SPEED:",speed)
    ids_name = ["suricata","snort","zeek"]
    filepaths = {}
    for name in ids_name:
        if not os.path.exists(f"./parallel/{str(name)}/perf_files"):
            print("Directory not found, creating directory...")
            os.makedirs(f"./parallel/{str(name)}/perf_files")
        filepaths[name] = f"./parallel/{name}/perf_files/ids_performance_log_{speed}.csv"
    # Start IDS as a subprocess
    print("Stating IDSs")
    temp = {}
    err = {}
    for name in ids_name:
        temp[name] = open(f"./{name}/tmp/temp.log", "w")
        err[name] = open(f"./{name}/tmp/err.log", "w")
    ## DEPENDING ON IDS USE DIFFERENT COMMANDS
    
    ids_proc={}
    for name, interface in zip(ids_name, interfaces):
        if name == "suricata":
            cmd = [
                "sudo", 
                "docker", 
                "exec", 
                "suricata-container", 
                "bash", 
                "-c",  
                f"cd .. && cd .. && cd usr/local/bin && ./suricata -i {interface} -c ../etc/suricata/suricata.yaml"  
            ]
            # cmd = ["sudo", suricata_path, "-i", interface, "-l", "./suricata/logs"]
            ids_proc[name] = subprocess.Popen(cmd, stdout=temp["suricata"], stderr=err["suricata"]) 
        elif name =="snort":
            cmd = [
                "sudo", 
                "docker", 
                "exec", 
                "snort-container", 
                "bash", 
                "-c",  
                f"cd bin && ./snort  -i {interface} -c ../etc/snort/snort.lua"  
            ]
            # cmd = ["sudo", snort_path, "-c", "../config/snort/snort.lua", "-i", interface]
            ids_proc[name] = subprocess.Popen(cmd, stdout=temp["snort"], stderr=err["snort"])
        elif name == "zeek":
            cmd = [
                "sudo", 
                "docker", 
                "exec", 
                "zeek-container", 
                "bash", 
                "-c",
                f"cd logs && zeek -C -i {interface} /usr/local/zeek/share/zeek/test-all-policy.zeek" 
            ]
            # cmd = ["sudo", zeek_path, "-i", interface], stdout=temp["zeek"]
            ids_proc[name] = subprocess.Popen(cmd, stderr=err["zeek"])
    # Wait for start
    print("Wait for all")
    wait_for_all()
    # Start tcp replay
    print("Starting tcp replay...", flush=True)
    time.sleep(1)
    
    tcpreplay_proc = {}
    tcpreplay_threads = {}
    for name, interface in zip(ids_name, interfaces):
        tcpreplay_thread = Thread(target=tcpreplay_execution, args=(name,loop,speed,interface,tcpreplay_proc))
        tcpreplay_threads[interface] = tcpreplay_thread
        tcpreplay_thread.start()        
            
    for interface, thread in tcpreplay_threads.items():
        thread.join()

    # Log performance in seperate thread for all IDSs
    monitor_threads = {}
    for name, interface in zip(ids_name, interfaces): #TODO: Wait for tcpreplay to start
        monitor_threads[name] = Thread(target=log_performance, args=(filepaths[name], f"{name}", tcpreplay_proc[interface]))
        monitor_threads[name].start()
    
    # Wait / Terminate tcp replay
    for interface in interfaces:    
        print(f"Wait for TCP replay to finish on {interface}...", flush=True)
        tcpreplay_proc[interface].wait()
    time.sleep(1)
    for interface in interfaces:
        if tcpreplay_proc[interface].poll() is None:  # Check if still running
            print(f"Terminating tcpreplay on {interface}...", flush=True)
            tcpreplay_proc[interface].terminate() 
    time.sleep(2)

    
    # Wait / Terminate ids_proc
    for name in ids_name:      
        if name == "suricata":
            subprocess.run([
                "docker", "exec", f"{name}-container",
                "bash", "-c", "kill -SIGINT $(pgrep -f suricata)"
            ])
        else:
            subprocess.run([
                "docker", "exec", f"{name}-container",
                "bash", "-c", f"kill -SIGINT $(pgrep -f {name})"
            ])
      
    
    # End / join thread
    print("Terminating monitor thread", flush=True)
    for name in ids_name:
        monitor_threads[name].join()

    # Check throughput is correct
    for interface in interfaces: 
        restart_interface(interface)
        if not check_tcpreplay_throughput(interface,speed):
            time.sleep(5)
            run(loop, speed, interfaces, recursion_count + 1, max_recursions) # Stop after 5 recursions
            
    drop_rate = {}
    total_packets = {}
    wait_for_all_drop_rates()
    for name in ids_name:
        if name == "suricata":
            drop_rate[name], total_packets[name] = extract_drop_rate_suricata()
        elif name == "snort":
            drop_rate[name], total_packets[name] = extract_drop_rate_snort()
        elif name == "zeek":
            drop_rate[name], total_packets[name] = extract_drop_rate_zeek()
        # Write drop rate to file
        with open(f"./parallel/{name}/perf_files/drop_rate_{speed}.txt", "w") as f:
            f.write(str(drop_rate[name]))
        with open(f"./parallel/{name}/perf_files/total_packets_{speed}.txt", "w") as f:
            f.write(str(total_packets[name]))
    
def wait_for_all_drop_rates():
    # Create a function that will wait until err or temp files contain "total packets"
    # while open(f"./suricata/tmp/temp.log", 'r').read().find("packets:") < 0 and open(f"./zeek/tmp/err.log", 'r').read().find(f"packets received on interface") < 0 and open(f"./snort/tmp/temp.log", 'r').read().find(f"received:") < 0:
    #     time.sleep(2)
    # time.sleep(10)
    while True:
        try:
            with open("./suricata/tmp/temp.log", 'r') as s:
                suricata_ready = re.search(r"packets: \d+", s.read()) is not None
        except FileNotFoundError:
            suricata_ready = False

        try:
            with open("./zeek/tmp/err.log", 'r') as z:
                zeek_ready = "packets received on interface" in z.read()
        except FileNotFoundError:
            zeek_ready = False

        try:
            with open("./snort/tmp/temp.log", 'r') as sn:
                snort_ready = re.search(r"received:\s*\d+", sn.read()) is not None
        except FileNotFoundError:
            snort_ready = False

        if suricata_ready and zeek_ready and snort_ready:
            break

        time.sleep(2)

def create_interface(interfaces):
    host_ip = "192.168.100.1/24"
    docker_ip = "192.168.100.2/24"
    host_interface = interface+"_host"
    docker_interface = interface+"_docker"
    for interface in interfaces:
        # Dummy is not enough need to be tunneled interface
        try:
            subprocess.run(["sudo", "ip", "link", "add", interface +"_host", "type", "veth", "peer", "name", interface+"_docker"], check=True)  
            subprocess.run(["sudo", "ip", "addr", "add", host_ip, "dev", host_interface], check=True) # This is to introduce IPREF3
            subprocess.run(["sudo", "ip", "addr", "add", docker_ip, "dev", docker_interface], check=True)
            # Bring them up
            subprocess.run(["sudo", "ip", "link", "set", interface+"_host", "up"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface+"_docker", "up"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to create interfaces {e}")
def remove_interface(interfaces):
    for x,interface in enumerate(interfaces):
        if x != 0:
            try: 
                subprocess.run(["sudo", "ip", "link", "delete", interface, "type", "dummy"],check=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed to create interfaces {e}")
def run_parallel(interface, first=10, last=60, step=10, loop=10):
    """
    Arguments for main():
    First - first mbits/s speed index
    Last - last mbits/s speed index
    Step - mbits/s speed index increase per iteration
    Loop - number of times to loop the pcap file
    """
    start = time.time()
    first = int(first)
    last = int(last)
    step = int(step)
    loop = int(loop)

    interfaces = [interface+"1", interface+"2"]
    interfaces.insert(0, interface)
    host_interfaces = []
    # Start interfaces
    for interface in interfaces:
            restart_interface(interface)
            host_interfaces.append(interface + "_host")
    
    for i in range(first,last,step):
        print("Speed:",i)
        loop = run(loop, i, host_interfaces)
        # Restart interfaces
        for interface in interfaces:
            restart_interface(interface)
        
    # Remove interfaces
    # remove_interface(interfaces) #TODO: Change from dummy to peer
    end = time.time()
    print("Runtime:",end-start)


