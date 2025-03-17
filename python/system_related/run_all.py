import time
import subprocess
import psutil
import csv
import sys
import re
import os
from threading import Thread
from vis_all import visualize
import argparse

def print_log(message):
    print(message)
    sys.stdout.flush()

def log_performance(log_file, process_name,tcp_proc):
    # Logs CPU & memory usage of the IDS process every 5 seconds 
    with open(log_file, "w", newline="") as f:
        # Writes to csv
        writer = csv.writer(f)
        writer.writerow(["Time", "CPU_Usage (%)", "Memory_Usage (%)"])  # CSV header
        psutil.cpu_percent(interval=1)
        while tcp_proc.poll() is None:
            # Find the process by name
            for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
                
                
                if process_name in proc.info["name"].lower():
                    
                    cpu_usage = proc.info["cpu_percent"] #CPU Utilization
                    rss_mem = proc.info["memory_info"].rss # Physical memory process used
                    
                    tot_mem = psutil.virtual_memory().total # Gets total physical memoryof computer
                    memory_percentage = (rss_mem / tot_mem) * 100

                    
                    writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cpu_usage, memory_percentage])
                    f.flush()

                    #print(proc.info["name"], ":", proc.info["cpu_percent"],":", memory_percentage, ":", proc.info["pid"])

            time.sleep(5)
            #psutil.process_iter.cache_clear()
    print_log("Logging complete")

def run(ids_name, loop, speed, pac_size, interface):
    if not os.path.exists(f"./{str(ids_name)}/perf_files_{str(pac_size)}"):
        print("Directory not found, creating directory...")
        os.mkdir(f"./{str(ids_name)}/perf_files_{str(pac_size)}")
    filepath = f"./{ids_name}/perf_files_{pac_size}/ids_performance_log_{speed}.csv"
    # Start IDS as a subprocess
    print_log(f"Starting {ids_name}...")
    
    temp = open(f"./{ids_name}/tmp/temp.log", "w")
    err = open(f"./{ids_name}/tmp/err.log", "w")
    ## DEPENDING ON IDS USE DIFFERENT COMMANDS
    # TODO: Change from path to ids name
    # TODO: function waiting for ids to start
    if ids_name == "suricata":
        ids_proc = subprocess.Popen(["sudo", "suricata", "-i", interface, "-l", "./suricata/logs"], stdout=temp, stderr=err) 
    elif ids_name == "snort3": # TODO Change the /usr/local/snort/bin/snort to snort?
        #ids_proc = subprocess.Popen(["sudo", "/usr/local/snort/bin/snort", "-c", "./snort3/config/snort.lua", "-i", interface], stdout=temp, stderr=err)
        ids_proc = subprocess.Popen(
            ["sudo", "/usr/local/snort/bin/snort", "-c", "./snort3/config/snort.lua", "-i", "eth0"], stdout=temp, stderr=err)
        
    elif ids_name == "zeek": # TODO Change the /usr/local/zeek/bin/zeekctl command to zeekctl?
        ids_proc = subprocess.Popen(["sudo", "/usr/local/zeek/bin/zeek", "-i", interface, "-C"], stdout=temp, stderr=err)
    # Wait for the IDS to send a start "signal"
    wait_for_start(ids_name, interface)
    #time.sleep(120) # Give the process 40 seconds to intitate.
    # Start tcp replay
    print_log("Starting tcp replay...")
    time.sleep(1)
    temp = open(f"./{ids_name}/tmp/temp_tcpreplay.log", "w")
    err = open(f"./{ids_name}/tmp/err_tcpreplay.log", "w")
    tcpreplay_proc = subprocess.Popen(["sudo", "tcpreplay", "-i", interface, f"--loop={loop}", f"--mbps={speed}", "./pcap/smallFlows.pcap"],stdout=temp, stderr=err)
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
        drop_rate, total_packets = extract_drop_rate_suricata()
    elif ids_name == "snort3":
        drop_rate, total_packets = extract_drop_rate_snort()
    elif ids_name == "zeek":
        drop_rate, total_packets = extract_drop_rate_zeek()
    # Write drop rate to file
    with open(f"./{ids_name}/perf_files_{pac_size}/drop_rate_{speed}.txt", "w") as f:
        f.write(str(drop_rate))
    with open(f"./{ids_name}/perf_files_{pac_size}/total_packets_{speed}.txt", "w") as f:
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
                
                print(f"Total Packets: {total_packets}")
                print(f"Dropped Packets: {dropped_packets}")
                print(f"Drop Rate: {drop_rate}%")
                return drop_rate, total_packets
    

def extract_drop_rate_snort():
    log = "./snort3/tmp/temp.log"
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
                
                print(f"Total Packets: {total_packets}")
                print(f"Dropped Packets: {dropped_packets}")
                print(f"Drop Rate: {drop_rate}%")
                return drop_rate, total_packets
    
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
    config_path = "./snort3/config/talos.lua"
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
    config_path = "/etc/suricata/suricata.yaml"
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

def wait_for_start(ids,interface):
    if ids == "suricata":
        while open(f"./{ids}/tmp/temp.log", 'r').read().find("Engine started") < 0:
            time.sleep(2)
    elif ids == "snort3":
        time.sleep(30)
        # while open(f"./{ids}/tmp/temp.log", 'r').read().find(f"++ [0] {interface}") < 0: 
        #     time.sleep(2)
    
    elif ids == "zeek":
        while open(f"./{ids}/tmp/err.log", 'r').read().find(f"listening on {interface}") < 0: 
            time.sleep(2)
    else:
        raise Exception("Wrong ids assigned.")


"""
Arguments for main():
First - first mbits/s speed index
Last - last mbits/s speed index
Step - mbits/s speed index increase per iteration
Loop - number of times to loop the pcap file
"""


def main():
    print("Current Working Directory:", os.getcwd())
    parser = argparse.ArgumentParser(description="Run system performance evaluation on all IDSs with set packet size.")
    parser.add_argument("packet_size", help="Choose packet sizes")
    parser.add_argument("interface",help="Which interface should the IDSs be run on?")
    args = parser.parse_args()
    loop = 10
    first = 20
    last = 200
    step = 10

    # TODO: Add a sudo su command for root access
    #subprocess.Popen(["sudo", "su"])
    
    
    change_packet_size(args.packet_size)
    for ids_name in ["snort3","suricata","zeek"]:
        for i in range(first,last,step):
            print("Running with speed:", i)
            run(ids_name, loop, i, args.packet_size, args.interface)
    
    visualize(args.packet_size)
    # Remove log files from zeek
    print("Current Working Directory 2:", os.getcwd())
    subprocess.Popen(["rm *.log"])
    
if __name__ == "__main__":
    main()

