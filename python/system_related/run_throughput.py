import time
import subprocess
import psutil
import csv
import re
import os
import glob
from threading import Thread

def check_zeek_interface(interface):
    new_lines = []
    filepath ="./../python/ids_configuration/zeek/config/zeek/node.cfg"
    # interface=veth_host
    with open(filepath,"r") as file:
        for line in file:
            if line == f"interface={interface}":
                break
    with open(filepath,"w") as file:
        for line in file:
            if line == f"interface={interface}":
                file.writelines(f"interface={interface}")        
   
        

def check_tcpreplay_throughput(ids_name,target_speed):
    threshold_percentage = 5  
    lower_bound = target_speed * (1 - threshold_percentage / 100)
    upper_bound = target_speed * (1 + threshold_percentage / 100)
    log = f"./{ids_name}/tmp/temp_tcpreplay.log"
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
        
    

def is_interface_valid(interface_name):
    return interface_name in psutil.net_if_addrs()

def wait_for_suricata_drop_rates():
    # Create a function that will wait until err or temp files contain "total packets"
    while open(f"./suricata/tmp/temp.log", 'r').read().find("packets:") < 0:
        time.sleep(2)

def wait_for_zeek_drop_rates():
    # Create a function that will wait until err or temp files contain "total packets"
    while open(f"./zeek/tmp/err.log", 'r').read().find(f"packets received on interface") < 0:
        time.sleep(2)

def wait_for_snort_drop_rates():
    # Create a function that will wait until err or temp files contain "total packets"
    while  open(f"./snort/tmp/temp.log", 'r').read().find(f"received:") < 0:
        time.sleep(2)

def wait_for_snort():
    while True:
        # Open and read each log file
        with open(f"./snort/tmp/temp.log", 'r') as file:
        
            status = "ntp:" in file.read()
            
            # If all conditions are met, exit the loop
            if status:
                break
        
        time.sleep(2)  # Sleep before checking again

def wait_for_zeek():
    while True:
        # Open and read each log file
        with open(f"./zeek/tmp/err.log", 'r') as file:
   
            status = "listening on" in file.read()
            
            # If all conditions are met, exit the loop
            if status:
                break
        
        time.sleep(2)  # Sleep before checking again

def wait_for_suricata():
    while True:
        # Open and read each log file
        with open(f"./suricata/tmp/temp.log", 'r') as file:
                   
            status = "Engine started" in file.read()
            
            # If all conditions are met, exit the loop
            if status:
                break
        
        time.sleep(2)  # Sleep before checking again

def log_performance(log_file, process_name,tcp_proc):
    # Logs CPU & memory usage of the IDS process every 5 seconds 
    with open(log_file, "w", newline="") as f:
        # Writes to csv
        writer = csv.writer(f)
        writer.writerow(["Time", "CPU_Usage (%)", "Memory_Usage (%)"])  # CSV header
        # psutil.cpu_percent(interval=10)
        # Initate a baseline for cpu precentage
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass  # Skip processes that may terminate or be inaccessible
        while tcp_proc.poll() is None:
            # Find the process by name
            total_cpu = 0
            total_mem = 0
            for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
    
                if process_name in proc.info["name"].lower():
                    
                    total_cpu += proc.info["cpu_percent"]       # Because Suricata is multithreaded it has multiple processes which need to be added togheter
                    total_mem += proc.info["memory_info"].rss

            tot_mem = psutil.virtual_memory().total
            memory_percentage = (total_mem / tot_mem) * 100
                    
            writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), total_cpu, memory_percentage])
            f.flush()

                    #print(proc.info["name"], ":", proc.info["cpu_percent"],":", memory_percentage, ":", proc.info["pid"])

            time.sleep(1)
            #psutil.process_iter.cache_clear()
    print("Logging complete", flush=True)

def run(ids_name, loop, speed, interface, pcap="smallFlows.pcap"):
    
    if pcap == "smallFlows.pcap":
        folder = "regular"
    else:
        folder = "latency"
        latency = pcap.split(".")[0].split("_")[-1].split("us")[0]
        print("LATENCY:",latency)

    # Fix filepath
    pcap="/pcap/"+pcap
    
    if folder == "regular":
        if not os.path.exists(f"./{folder}/{str(ids_name)}/perf_files"):
            print("Directory not found, creating directory...")
            os.makedirs(f"./{folder}/{str(ids_name)}/perf_files")
        filepath = f"./{folder}/{ids_name}/perf_files/ids_performance_log_{speed}.csv"
    elif folder == "latency":
        if not os.path.exists(f"./{folder}/{str(ids_name)}/perf_files"):
            print("Directory not found, creating directory...")
            os.makedirs(f"./{folder}/{str(ids_name)}/perf_files")
        filepath = f"./{folder}/{ids_name}/perf_files/ids_performance_log_{latency}.csv"
    # Start IDS as a subprocess
    print(f"Starting {ids_name}...", flush=True)
    
    temp = open(f"./{ids_name}/tmp/temp.log", "w")
    err = open(f"./{ids_name}/tmp/err.log", "w")
    ## DEPENDING ON IDS USE DIFFERENT COMMANDS

    if ids_name == "suricata":
        cmd = [
            "sudo", 
            "docker", 
            "exec", 
            "suricata-container", 
            "bash", 
            "-c",  
            f"cd .. && cd .. && cd usr/local/bin && ./suricata -i {interface} -c ../etc/suricata/suricata.yaml"  
        ]
        # command = ["sudo", suricata_path, "-i", interface, "-l", "./suricata/logs"]
        ids_proc = subprocess.Popen(cmd, stdout=temp, stderr=err) 
        wait_for_suricata()
    elif ids_name == "snort":
        cmd = [
            "sudo", 
            "docker", 
            "exec", 
            "snort-container", 
            "bash", 
            "-c",  
            f"cd bin && ./snort  -i {interface} -c ../etc/snort/snort.lua"  
        ]
        # command = ["sudo", snort_path, "-c", "../config/snort/snort.lua", "-i", interface]
        ids_proc = subprocess.Popen(cmd, stdout=temp, stderr=err)
        wait_for_snort()
    elif ids_name == "zeek": 
        cmd = [
            "sudo", 
            "docker", 
            "exec", 
            "zeek-container", 
            "bash", 
            "-c",
            f"cd logs && zeek -C -i {interface} /usr/local/zeek/share/zeek/test-all-policy.zeek" 
        ]
        # command = ["sudo", zeek_path, "-i", interface]
        ids_proc = subprocess.Popen(cmd, stdout=temp, stderr=err)
        wait_for_zeek()
    
    if ids_name == "snort":
        time.sleep(10)      # TODO: change from sleep to something else - Give the process 10 seconds to intitate.
                            # TODO: Maybe this should be scaled with the throughput for all IDSs.

    # Start tcp replay
    print("Starting tcp replay...", flush=True)
    time.sleep(1)
    temp = open(f"./{ids_name}/tmp/temp_tcpreplay.log", "w")
    err = open(f"./{ids_name}/tmp/err_tcpreplay.log", "w")
    cmd = [
        "sudo","docker", "exec", 
        f"{ids_name}-container",
        "tcpreplay",
        "-i", interface,
        f"--loop={loop}",
        f"--mbps={speed}",
        pcap
    ]
    # cmd = ["sudo", "tcpreplay", "-i", interface, f"--loop={loop}", f"--mbps={speed}", "./pcap/smallFlows.pcap"]
    tcpreplay_proc = subprocess.Popen(cmd,stdout=temp, stderr=err)
    # Log performance in seperate thread while {ids_name} is running and until tcpreplay is done
    monitor_thread = Thread(target=log_performance, args=(filepath, f"{ids_name}", tcpreplay_proc))
    monitor_thread.start()
    time.sleep(1)
    # Wait / Terminate tcp replay
    print("Wait for TCP replay to finish", flush=True)
    tcpreplay_proc.wait()
    time.sleep(1)
    print(f"Terminating tcpreplay..", flush=True)
    tcpreplay_proc.terminate()
    time.sleep(2)
    # Wait / Terminate ids_proc
    print(f"Termating {ids_name}..", flush=True)

    if ids_name == "snort":
        subprocess.run([
            "docker", "exec", f"{ids_name}-container",
            "bash", "-c", f"kill -SIGINT $(pgrep -fx './snort -i veth_host -c ../etc/snort/snort.lua')"
        ])
    else:
        # subprocess.run(["docker", "exec", f"{ids_name}-container", "pkill", "-SIGINT", f"{ids_name}"])
        subprocess.run([
            "docker", "exec", f"{ids_name}-container",
            "bash", "-c", f"kill -SIGINT $(pgrep -f {ids_name})"
        ])
    time.sleep(1)
    print(f"Wait for {ids_name} to finish", flush=True)
    
    
    # End / join thread
    print("Terminating monitor thread", flush=True)
    monitor_thread.join()
    # Check if throughput is correct
    if not check_tcpreplay_throughput(ids_name,speed): # If not a match then restart with new loop length 
        run(ids_name, loop, speed, interface, pcap)
        
    # Extract drop rate from ids
    if ids_name == "suricata":
        wait_for_suricata_drop_rates()
        drop_rate, total_packets = extract_drop_rate_suricata()
    elif ids_name == "snort":
        wait_for_snort_drop_rates()
        drop_rate, total_packets = extract_drop_rate_snort()
    elif ids_name == "zeek":
        wait_for_zeek_drop_rates()
        drop_rate, total_packets = extract_drop_rate_zeek()
    # Write drop rate to file
    if folder == "regular":
        with open(f"./{folder}/{ids_name}/perf_files/drop_rate_{speed}.txt", "w") as f:
            f.write(str(drop_rate))
        with open(f"./{folder}/{ids_name}/perf_files/total_packets_{speed}.txt", "w") as f:
            f.write(str(total_packets))
    elif folder == "latency":
        with open(f"./{folder}/{ids_name}/perf_files/drop_rate_{latency}.txt", "w") as f:
            f.write(str(drop_rate))
        with open(f"./{folder}/{ids_name}/perf_files/total_packets_{latency}.txt", "w") as f:
            f.write(str(total_packets))
    
def extract_drop_rate_zeek():
    log = "./zeek/tmp/err.log"
    with open(log, "r") as file:
        for line in file:
            match = re.search(r"(\d+) packets received on interface (\S+), (\d+) \(([\d.]+)%\) dropped", line)
            if match:
                total_packets = int(match.group(1))
                dropped_packets = int(match.group(3))
                drop_rate = float(match.group(4))
                print(f"Total Packets: {total_packets} | Dropped Packets: {dropped_packets} | Drop Rate: {drop_rate}%")
                drop_rate,tcpreplay_total_packets = check_drop_rate(drop_rate,total_packets,"zeek")
                print(f"CHECK: Total Packets: {tcpreplay_total_packets} | Dropped Packets: {dropped_packets} | Drop Rate: {drop_rate}%")

                
                return drop_rate, total_packets
    

def extract_drop_rate_snort():
    log = "./snort/tmp/temp.log"
    total_packets = None
    dropped_packets = None

    with open(log, "r") as file:
        for line in file:
            rec_match = re.search(r"\s*received:\s*(\d+)", line)
            drop_match = re.search(r"\s*dropped:\s*(\d+)", line)

            if rec_match:
                total_packets = int(rec_match.group(1))

            if drop_match:
                dropped_packets = int(drop_match.group(1))

    if total_packets is not None and dropped_packets is not None:
        drop_rate = (dropped_packets / total_packets) * 100 if total_packets > 0 else 0.0
        
        print(f"Total Packets: {total_packets} | Dropped Packets: {dropped_packets} | Drop Rate: {drop_rate:.2f}%")
        drop_rate,tcpreplay_total_packets = check_drop_rate(drop_rate,total_packets,"snort")
        print(f"CHECK: Total Packets: {tcpreplay_total_packets} | Drop Rate: {drop_rate:.2f}%")

        return drop_rate, total_packets # Should save what the ids thinks are the total number of packets
    else: 
        # No dropped packets, means 0 drop rate
        drop_rate = 0.0
        print(f"Total Packets: {total_packets} | Dropped Packets: {dropped_packets} | Drop Rate: {drop_rate:.2f}%")
        drop_rate,tcpreplay_total_packets = check_drop_rate(drop_rate,total_packets,"snort")
        print(f"CHECK: Total Packets: {tcpreplay_total_packets} | Drop Rate: {drop_rate:.2f}%")

        return drop_rate, total_packets


def extract_drop_rate_suricata():
    log = "./suricata/tmp/temp.log"
    with open(log, "r") as file:
        for line in file:
            match = re.search(r"i: device: (\S+): packets: (\d+), drops: (\d+) \(([\d.]+)%\), invalid chksum: (\d+)", line)
            if match:
                total_packets = int(match.group(2))   
                dropped_packets = int(match.group(3))    
                drop_rate = float(match.group(4))       
                
                print(f"Total Packets: {total_packets} | Dropped Packets: {dropped_packets} | Drop Rate: {drop_rate}%")
            
                drop_rate,tcpreplat_total_packets = check_drop_rate(drop_rate,total_packets,"suricata")
                print(f"CHECK: Total Packets: {tcpreplat_total_packets} | Drop Rate: {drop_rate:.2f}%")

                return drop_rate, total_packets
        return 0.0, 0
    

def check_drop_rate(ids_drop_rate,ids_total_packets,ids_name): 
    tcpreplay_total_packets = 0
    log = f"./{ids_name}/tmp/temp_tcpreplay.log"
    with open(log, "r") as file:
        for line in file:
            match = re.search(r"Successful packets:\s*(\d+)", line)
            if match:
                tcpreplay_total_packets = int(match.group(1))  

    if tcpreplay_total_packets != ids_total_packets and ids_total_packets < tcpreplay_total_packets:

        delta = tcpreplay_total_packets - ids_total_packets
        ids_dropped_packets = ids_total_packets * (ids_drop_rate/100) # Must be divided from % to decimal
        new_drop_rate = ((ids_dropped_packets + delta)/tcpreplay_total_packets)*100
        return new_drop_rate,tcpreplay_total_packets
    
    else:
        return ids_drop_rate,ids_total_packets

def restart_interface(interface):
    host_if = f"{interface}_host"
    docker_if = f"{interface}_docker"
    # Remove old interface
    if is_interface_valid(host_if):
        print("This interface already exists")
        subprocess.run(["sudo", "ip", "link", "delete", host_if], check=False)

    # Create the veth pair
    subprocess.run(["sudo", "ip", "link", "add", host_if, "type", "veth", "peer", "name", docker_if], check=True)

    # Set veth_host up
    subprocess.run(["sudo", "ip", "link", "set", host_if, "up"], check=True)

    # Set veth_docker up
    subprocess.run(["sudo", "ip", "link", "set", docker_if, "up"], check=True)



def run_throughput(interface, first=10, last=60, step=10, loop=10):
    start = time.time()
    """
    Creating an interface:  sudo ip link add veth_host type veth peer name veth_docker
                            sudo ip link set veth_host up
                            sudo ip link set veth_docker up
    """
    first = int(first)
    last = int(last)
    step = int(step)
    loop = int(loop)

    
    restart_interface(interface) # This will create an interface link between interface_name_host and interface_name_docker
    host_interface = (interface+"_host")
    if not is_interface_valid(host_interface): # Check if interface is valid and exists
        raise Exception(f"Error: interface: {host_interface} does not exist.")
    
    
    for ids_name in ["suricata","zeek","snort"]:
        # latency_eval(ids_name,10,512,interface)
        for i in range(first,last,step):
            print("Running with speed:", i)
            restart_interface(interface) # Restart the interface between runs so snort can shutdown
            run(ids_name, loop, i, host_interface)
    
    # visualize()
    runtime = time.time()-start
    print("Runtime:",runtime)
    



""" --Packet Size Stuff-- """

def change_packet_size(packet_size):
    """ 
    Change the packet size to a new int, for all IDSs
    To implement a new IDS add the function for changing the packet size here 
    """
    change_packet_size_snort(packet_size)
    change_packet_size_suricata(packet_size)
    change_packet_size_zeek(packet_size) 

def change_packet_size_snort(packet_size):
    # Change config path to match your system
    config_path = "../config/snort/talos.lua"
    if not os.path.exists(config_path): 
        print("Path for Snort config file not available, have you specified the correct path?")
        return
    # Search for line to change with re
    with open(config_path, "r") as file:
        data = file.read()
    
    data = re.sub(r"(\b\s*snaplen\s*=\s*)(\d+)", rf"snaplen = {str(packet_size)}", data)    
    with open(config_path,"w") as file:
        file.write(data)
    # Restart IDS
    #subprocess.Popen(["systemctl restart snort"])

def change_packet_size_suricata(packet_size):
    # Change config path to match your system (path for elias)
    config_path = "../config/suricata/suricata.yaml"
    # home_path = "~"
    if not os.path.exists(config_path): 
        print("Path for suricata config file not available, have you specified the correct path?")
        return
    # subprocess.Popen(["sudo", "cp", f"{config_path}", f"{home_path}"]) # Move to home directory for file premissions
    # Search for line to change with re
    with open(config_path, "r") as file:
        data = file.read()
    
    data = re.sub(r"(\s*#?max-pending-packets:\s*)(\d+)", rf"\nmax-pending-packets: {str(packet_size)}", data)
    with open(config_path, "w") as file:
        file.write(data)
    # Move it back
    # subprocess.Popen(["sudo", "mv", "suricata.yaml", "/etc/suricata/"])
    # Restart IDS
    #subprocess.Popen(["suricata-update"])

    

def change_packet_size_zeek(packet_size):
    # Change config path to match your system (path for elias)
    config_path = "../config/zeek/zeekctl-config.sh"
    if not os.path.exists(config_path): 
        print("Path for Zeek config file not available, have you specified the correct path?")
        return
    # Search for line to change with re
    with open(config_path, "r")  as file:
        data = file.read()
    data = re.sub(r'(\bpcapsnaplen\s*=\s*")(\d+)(")', rf'pcapsnaplen="{str(packet_size)}\3', data) # Only change the integer at the end
    with open(config_path, "w") as file: # Replace string with new int value
        file.write(data) 
    # Restart IDS
    # proc = subprocess.Popen(["sudo", "/usr/local/zeek/bin/zeekctl", "deploy"])
    # time.sleep(20)
    # proc.terminate()
    