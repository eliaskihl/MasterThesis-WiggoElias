
import time
import subprocess
import time
import psutil
import csv
import sys
import re
import os
from threading import Thread
from vis_all import visualize

def print_log(message):
    print(message)
    sys.stdout.flush()

def log_performance(log_file, process_name,tcp_proc):
    # Logs CPU & memory usage of the IDS process every 5 seconds 
    with open(log_file, "w", newline="") as f:
        # Writes to csv
        writer = csv.writer(f)
        writer.writerow(["Time", "CPU_Usage (%)", "Memory_Usage (%)"])  # CSV header
        psutil.cpu_percent(interval=10)
        while tcp_proc.poll() is None:
            # Find the process by name
            for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
                
                
                if process_name in proc.info["name"].lower():
                    
                    cpu_usage = proc.info["cpu_percent"]
                    rss_mem = proc.info["memory_info"].rss # rss mem in bytes?
                    # Get the total system memory (in bytes)
                    tot_mem = psutil.virtual_memory().total
                    memory_percentage = (rss_mem / tot_mem) * 100

                    
                    writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cpu_usage, memory_percentage])
                    f.flush()

                    print(proc.info["name"], ":", proc.info["cpu_percent"],":", memory_percentage, ":", proc.info["pid"])

            time.sleep(5)
            #psutil.process_iter.cache_clear()
    print_log("Logging complete")

def run(ids_name, loop, speed, pac_size):
    if not os.path.exists(f"python/system_related/{ids_name}/perf_files_{pac_size}"):
        print("Directory not found, creating directory...")
        os.mkdir(f"python/system_related/{ids_name}/perf_files_{pac_size}")
    filepath = f"python/system_related/{ids_name}/perf_files_{pac_size}/ids_performance_log_{speed}.csv"
    # Start {ids_name} as subprocess
    print_log(f"Starting {ids_name}...")
    
    temp = open(f"python/system_related/{ids_name}/tmp/temp.log", "w")
    err = open(f"python/system_related/{ids_name}/tmp/err.log", "w")
    ## DEPENDING ON IDS USE DIFFERENT COMMANDS
    if ids_name == "suricata":
        ids_proc = subprocess.Popen(["sudo", "suricata", "-i", "eth0", "-l", "./python/system_related/suricata/logs"], stdout=temp, stderr=err) 
    elif ids_name == "snort3": # TODO Change the /usr/local/snort/bin/snort to snort?
        ids_proc = subprocess.Popen(["sudo", "/usr/local/snort/bin/snort", "-c", "python/system_related/snort3/config/snort.lua", "-i", "eth0", "-l", "./python/system_related/snort3/logs"], stdout=temp, stderr=err)
    elif ids_name == "zeek": # TODO Change the /usr/local/zeek/bin/zeekctl command to zeekctl?
        ids_proc = subprocess.Popen(["sudo", "/usr/local/zeek/bin/zeek", "-i", "eth0"], stdout=temp, stderr=err)
        #ids_proc = subprocess.Popen(["sudo", "/usr/local/zeek/bin/zeekctl", "start"], stdout=temp, stderr=err)
        #ids_proc = subprocess.Popen(["docker", "run", "--rm", "--net=host", "--name", "zeek-live", "zeek/zeek", "zeek", "-i", "eth0",], stdout=temp, stderr=err)
    time.sleep(40) # Give the process 40 seconds to intitate.
    # Start tcp replay
    print_log("Starting tcp replay...")
    time.sleep(1)
    temp = open(f"python/system_related/{ids_name}/tmp/temp_tcpreplay.log", "w")
    err = open(f"python/system_related/{ids_name}/tmp/err_tcpreplay.log", "w")
    tcpreplay_proc = subprocess.Popen(["sudo", "tcpreplay", "-i", "eth0", f"--loop={loop}", f"--mbps={speed}", "python/system_related/pcap/bigFlows.pcap"],stdout=temp, stderr=err)
    # Log performance in seperate thread while {ids_name} is running and until tcpreplay is done
    monitor_thread = Thread(target=log_performance, args=(filepath, f"{ids_name}", tcpreplay_proc))
    monitor_thread.start()
    time.sleep(1)
    # Wait / Terminate tcp replay
    print_log("Wait for TCP replay to finish")
    tcpreplay_proc.wait()
    time.sleep(1)
    print_log(f"Terminating tcpreplay..")
    tcpreplay_proc.terminate()
    time.sleep(2)
    # Wait / Terminate ids_proc
    print_log(f"Termating {ids_name}..")
    ids_proc.terminate()
    time.sleep(1)
    print_log(f"Wait for {ids_name} to finish")
    ids_proc.wait()
    
    # End / join thread
    print_log("Terminating monitor thread")
    monitor_thread.join()

    # Extract drop rate from ids
    if ids_name == "suricata":
        drop_rate = extract_drop_rate_suricata()
    elif ids_name == "snort3":
        drop_rate = extract_drop_rate_snort()
    elif ids_name == "zeek":
        drop_rate = extract_drop_rate_zeek()
    # Write drop rate to file
    with open(f"python/system_related/{ids_name}/perf_files/drop_rate_{speed}.txt", "w") as f:
        f.write(str(drop_rate))
def extract_drop_rate_zeek():
    log = "python/system_related/zeek/tmp/err.log"
    with open(log, "r") as file:
        for line in file:
            match = re.search(r"(\d+) packets received on interface (\S+), (\d+) \(([\d.]+)%\) dropped", line)
            if match:
                total_packets = int(match.group(1))
                dropped_packets = int(match.group(3))
                drop_rate = float(match.group(4))
                
                print(f"Total Packets: {total_packets}")
                print(f"Dropped Packets: {dropped_packets}")
                print(f"Drop Rate: {drop_rate}%")
                return drop_rate
    

def extract_drop_rate_snort():
    log = "python/system_related/snort3/tmp/temp.log"
    # Find line with "dropped" and "received"
    with open(log, "r") as file:
        for line in file:
            
            rec_match = re.search(r"\s*received:\s*(\d+)\s*", line)
            drop_match = re.search(r"\s*dropped:\s*(\d+)\s*", line)
            
            if rec_match:
                total_packets = int(rec_match.group(1))
            if drop_match:
                dropped_packets = int(drop_match.group(1))
                if total_packets > 0:
                    drop_rate = (dropped_packets / total_packets) * 100
                else: 
                    drop_rate = 0.0
                print(f"Total Packets: {total_packets}")
                print(f"Dropped Packets: {dropped_packets}")
                print(f"Drop Rate: {drop_rate}%")
                return drop_rate

def extract_drop_rate_suricata():
    log = "python/system_related/suricata/tmp/temp.log"
    with open(log, "r") as file:
        for line in file:
            match = re.search(r"i: device: (\S+): packets: (\d+), drops: (\d+) \(([\d.]+)%\), invalid chksum: (\d+)", line)
            if match:
                total_packets = int(match.group(2))   
                dropped_packets = int(match.group(3))    
                drop_rate = float(match.group(4))       
                
                print(f"Total Packets: {total_packets}")
                print(f"Dropped Packets: {dropped_packets}")
                print(f"Drop Rate: {drop_rate}%")
                return drop_rate
    
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
    config_path = "python/system_related/snort3/config/talos.lua"
    if not os.path.exists(config_path): 
        print("Path for Snort config file not available, have you specified the correct path?")
        return
    # Search for line to change with re
    with open(config_path, "r") as file:
        data = file.read()
    print(data)
    data = re.sub(r"(\b\s*snaplen\s*=\s*)(\d+)", rf"snaplen = {str(packet_size)}", data)    
    with open(config_path,"w") as file:
        file.write(data)
    # Restart IDS
    #subprocess.Popen(["systemctl restart snort"])

def change_packet_size_suricata(packet_size):
    # Change config path to match your system (path for elias)
    config_path = "/etc/suricata/suricata.yaml"
    # home_path = "~"
    if not os.path.exists(config_path): 
        print("Path for suricata config file not available, have you specified the correct path?")
        return
    # subprocess.Popen(["sudo", "cp", f"{config_path}", f"{home_path}"]) # Move to home directory for file premissions
    # Search for line to change with re
    with open(config_path, "r") as file:
        data = file.read()
    print(data)
    data = re.sub(r"(\s*#?max-pending-packets:\s*)(\d+)", rf"\nmax-pending-packets: {str(packet_size)}", data)
    with open(config_path, "w") as file:
        file.write(data)
    # Move it back
    # subprocess.Popen(["sudo", "mv", "suricata.yaml", "/etc/suricata/"])
    # Restart IDS
    #subprocess.Popen(["suricata-update"])

    

def change_packet_size_zeek(packet_size):
    # Change config path to match your system (path for elias)
    config_path = "/usr/local/zeek/share/zeekctl/scripts/zeekctl-config.sh"
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
    
def main(first, last, step, loop):
    # TODO: Add a sudo su command for root access
    root = subprocess.Popen(["sudo", "su"])
    root.terminate()
    root.wait()
    packet_sizes = [512]
    
    for size in packet_sizes:
        change_packet_size(size)
        for ids_name in ["snort3","suricata","zeek"]:
            for i in range(first, last, step):
                print("Running with speed:", i)
                run(ids_name, loop, i, size)
    
    visualize()

"""
Arguments for main():
First - first mbits/s speed index
Last - last mbits/s speed index
Step - mbits/s speed index increase per iteration
Loop - number of times to loop the pcap file
"""

main(100,200,100,1)

