import time
import subprocess
from threading import Thread
import os

from vis_all import visualize
import argparse
from dotenv import load_dotenv,find_dotenv
from run_all import change_packet_size,run,log_performance,extract_drop_rate_suricata,extract_drop_rate_snort,extract_drop_rate_zeek
""""
Arguments for main():
First - first mbits/s speed index
Last - last mbits/s speed index
Step - mbits/s speed index increase per iteration
Loop - number of times to loop the pcap file
"""

def wait_for_all():
    while True:
        # Open and read each log file
        with open(f"./suricata/tmp/temp.log", 'r') as suricata_file, \
             open(f"./zeek/tmp/err.log", 'r') as zeek_file, \
             open(f"./snort3/tmp/temp.log", 'r') as snort_file:
            
            suricata_status = "Engine started" in suricata_file.read()
            zeek_status = "listening on" in zeek_file.read()
            snort_status = "ntp:" in snort_file.read()
            
            # If all conditions are met, exit the loop
            if suricata_status and zeek_status and snort_status:
                break
        
        time.sleep(2)  # Sleep before checking again


def run(loop, speed, pac_size, interfaces):
    dotenv_path = find_dotenv()
    load_dotenv(dotenv_path)
    snort_path = os.getenv("SNORT_PATH")
    zeek_path = os.getenv("ZEEK_PATH")
    suricata_path = os.getenv("SURICATA_PATH")
    ids_name = ["suricata","snort3","zeek"]
    filepaths = {}
    for name in ids_name:
        if not os.path.exists(f"./{str(name)}/perf_files_{str(pac_size)}"):
            print("Directory not found, creating directory...")
            os.mkdir(f"./{str(name)}/perf_files_{str(pac_size)}")
        filepaths[name] = f"./{name}/perf_files_{pac_size}/ids_performance_log_{speed}.csv"
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
            ids_proc[name] = subprocess.Popen(["sudo", suricata_path, "-i", interface, "-l", "./suricata/logs"], stdout=temp["suricata"], stderr=err["suricata"]) 
        elif name =="snort3":
            ids_proc[name] = subprocess.Popen(["sudo", snort_path, "-c", "../config/snort3/snort.lua", "-i", interface], stdout=temp["snort3"], stderr=err["snort3"])
        elif name == "zeek":
            ids_proc[name] = subprocess.Popen(["sudo", zeek_path, "-i", interface], stdout=temp["zeek"], stderr=err["zeek"])
    # Wait for start
    print("wait for all")
    wait_for_all()
    # Start tcp replay
    print("Starting tcp replay...")
    time.sleep(1)
    
    tcpreplay_proc = {}
    for interface in interfaces:
        if not os.path.exists(f"./dir_{interface}/tmp/"):
            print("Directory not found, creating directory...")
            os.makedirs(f"./dir_{interface}/tmp/")
        with open(f"./dir_{interface}/tmp/temp_tcpreplay.log", "w") as temp, \
        open(f"./dir_{interface}/tmp/err_tcpreplay.log", "w") as err:
            try:
                tcpreplay_proc[interface] = subprocess.Popen(["sudo", "tcpreplay", "-i", interface, f"--loop={loop}", f"--mbps={speed}", "./pcap/smallFlows.pcap"],
                    stdout=temp, stderr=err
                )
                time.sleep(1) # Give process time to start
            except Exception as e:
                print(f"Error starting tcpreplay on {interface}: {e}")
                tcpreplay_proc[interface] = None

    # Log performance in seperate thread for all IDSs
    monitor_threads = {}
    for name, interface in zip(ids_name, interfaces):
        monitor_threads[name] = Thread(target=log_performance, args=(filepaths[name], f"{name}", tcpreplay_proc[interface]))
        monitor_threads[name].start()
    
    # Wait / Terminate tcp replay
    for interface in interfaces:    
        print(f"Wait for TCP replay to finish on {interface}...")
        tcpreplay_proc[interface].wait()
    time.sleep(1)
    for interface in interfaces:
        if tcpreplay_proc[interface].poll() is None:  # Check if still running
            print(f"Terminating tcpreplay on {interface}...")
            tcpreplay_proc[interface].terminate()
    time.sleep(2)
    
    # Wait / Terminate ids_proc
    for name in ids_name:      
        print(f"Termating IDS: {name}..")
        ids_proc[name].terminate()
        
      
    for name in ids_name:
        print(f"Wait for {name} to finish")
        ids_proc[name].wait()
    
    # End / join thread
    print("Terminating monitor thread")
    for name in ids_name:
        monitor_threads[name].join()

    drop_rate = {}
    total_packets = {}
    wait_for_all_drop_rates()
    for name in ids_name:
        if name == "suricata":
            drop_rate[name], total_packets[name] = extract_drop_rate_suricata()
        elif name == "snort3":
            drop_rate[name], total_packets[name] = extract_drop_rate_snort()
        elif name == "zeek":
            drop_rate[name], total_packets[name] = extract_drop_rate_zeek()
        # Write drop rate to file
        with open(f"./{name}/perf_files_{pac_size}/drop_rate_{speed}.txt", "w") as f:
            f.write(str(drop_rate[name]))
        with open(f"./{name}/perf_files_{pac_size}/total_packets_{speed}.txt", "w") as f:
            f.write(str(total_packets[name]))

def wait_for_all_drop_rates():
    # Create a function that will wait until err or temp files contain "total packets"
    while open(f"./suricata/tmp/temp.log", 'r').read().find("packets:") < 0 and open(f"./zeek/tmp/err.log", 'r').read().find(f"packets received on interface") < 0 and open(f"./snort3/tmp/temp.log", 'r').read().find(f"received:") < 0:
        time.sleep(2)

def create_interface(interfaces):
    for interface in interfaces:
        try:
            subprocess.run(["sudo", "ip", "link", "add", interface, "type", "dummy"], check=True)  
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to create interfaces {e}")
def remove_interface(interfaces):
    for x,interface in enumerate(interfaces):
        if x != 0:
            try: 
                subprocess.run(["sudo", "ip", "link", "delete", interface, "type", "dummy"],check=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed to create interfaces {e}")
def main():
    # Run in parallel
    # TODO: Define 3 different ranges for the IDS to run in 
    parser = argparse.ArgumentParser(description="Run system performance evaluation on all IDSs with set packet size.")
    parser.add_argument("packet_size", help="Choose packet sizes")
    parser.add_argument("interface",help="Which interface should the IDSs be run on?")
    args = parser.parse_args()
    loop = 10
    first = 10
    last = 151
    step = 1000

    # TODO: Add a sudo su command for root access
    #subprocess.Popen(["sudo", "su"])
    
    # Change packet size
    change_packet_size(args.packet_size)
    interfaces = ["eth1","eth2"]
    create_interface(interfaces)
    interfaces.insert(0, args.interface)
    for i in range(first,last,step):
        print("Speed:",i)
        run(loop, i, args.packet_size, interfaces)
        
        
    visualize(args.packet_size)
    # Remove interfaces
    remove_interface(interfaces)
    # Remove log files from zeek
    subprocess.Popen(["rm", "./python/system_related/*.log"])
    
if __name__ == "__main__":
    main()


