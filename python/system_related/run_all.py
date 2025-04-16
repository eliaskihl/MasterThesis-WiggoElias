import time
import subprocess
import psutil
import csv
import re
import os
from threading import Thread
from vis_all import visualize
import argparse


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
        psutil.cpu_percent(interval=10)
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
    print("Logging complete")

def run(ids_name, loop, speed, interface):
    
    
    if not os.path.exists(f"./{str(ids_name)}/perf_files"):
        print("Directory not found, creating directory...")
        os.makedirs(f"./{str(ids_name)}/perf_files")
    filepath = f"./{ids_name}/perf_files/ids_performance_log_{speed}.csv"
    # Start IDS as a subprocess
    print(f"Starting {ids_name}...")
    
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
        time.sleep(30)      # TODO: change from sleep to something else - Give the process 10 seconds to intitate.
                            # TODO: Maybe this should be scaled with the throughput for all IDSs.

    # Start tcp replay
    print("Starting tcp replay...")
    time.sleep(1)
    temp = open(f"./{ids_name}/tmp/temp_tcpreplay.log", "w")
    err = open(f"./{ids_name}/tmp/err_tcpreplay.log", "w")
    cmd = [
        "docker", "exec", 
        f"{ids_name}-container",
        "tcpreplay",
        "-i", interface,
        f"--loop={loop}",
        f"--mbps={speed}",
        "/pcap/smallFlows.pcap"
    ]
    # cmd = ["sudo", "tcpreplay", "-i", interface, f"--loop={loop}", f"--mbps={speed}", "./pcap/smallFlows.pcap"]
    tcpreplay_proc = subprocess.Popen(cmd,stdout=temp, stderr=err)
    # Log performance in seperate thread while {ids_name} is running and until tcpreplay is done
    monitor_thread = Thread(target=log_performance, args=(filepath, f"{ids_name}", tcpreplay_proc))
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
    print(f"Termating {ids_name}..")

    if ids_name == "suricata":
        subprocess.run([
            "docker", "exec", f"{ids_name}-container",
            "bash", "-c", "kill -SIGINT $(pgrep -f suricata)"
        ])
    else:
        subprocess.run(["docker", "exec", f"{ids_name}-container", "pkill", "-SIGINT", f"{ids_name}"])
    time.sleep(1)
    print(f"Wait for {ids_name} to finish")
    
    
    # End / join thread
    print("Terminating monitor thread")
    monitor_thread.join()

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
    with open(f"./{ids_name}/perf_files/drop_rate_{speed}.txt", "w") as f:
        f.write(str(drop_rate))
    with open(f"./{ids_name}/perf_files/total_packets_{speed}.txt", "w") as f:
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
        print(f"Total Packets: {total_packets}")
        print(f"Dropped Packets: {dropped_packets}")
        print(f"Drop Rate: {drop_rate:.2f}%")
        return drop_rate, total_packets
    else:
        print("Could not find both received and dropped packet stats.")
        return None, None


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
    


def check_actual_drop_rate(ids_name): #TODO: The total recorded packets should match the tcp replay packet otherwise a new drop rate should be recorded
    pass

def main():
    print("Current Working Directory:", os.getcwd())
    parser = argparse.ArgumentParser(description="Run system performance evaluation on all IDSs with set packet size.")
    # parser.add_argument("packet_size", help="Choose packet sizes")
    parser.add_argument("interface",help="Which interface should the IDSs be run on?")
    args = parser.parse_args()
    loop = 10
    first = 50
    last = 51
    step = 100
    # TODO: Processes names are wrong, snort and zeek are barely logging resource consumption values.
    
    # change_packet_size(args.packet_size)
    for ids_name in ["snort","zeek","suricata"]:
        for i in range(first,last,step):
            print("Running with speed:", i)
            run(ids_name, loop, i, args.interface)
    
    # visualize()
    
    
    
if __name__ == "__main__":
    main()


