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
             open(f"./snort/tmp/temp.log", 'r') as snort_file:
            
            suricata_status = "Engine started" in suricata_file.read()
            zeek_status = "listening on" in zeek_file.read()
            snort_status = "ntp:" in snort_file.read()
            
            # If all conditions are met, exit the loop
            if suricata_status and zeek_status and snort_status:
                break
        
        time.sleep(2)  # Sleep before checking again


def run(loop, speed, pac_size, interfaces):

    ids_name = ["suricata","snort","zeek"]
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
    print("wait for all")
    wait_for_all()
    # Start tcp replay
    print("Starting tcp replay...")
    time.sleep(1)
    
    tcpreplay_proc = {}
    for name, interface in zip(ids_name, interfaces):
        if not os.path.exists(f"./dir_{interface}/tmp/"):
            print("Directory not found, creating directory...")
            os.makedirs(f"./dir_{interface}/tmp/")
        with open(f"./dir_{interface}/tmp/temp_tcpreplay.log", "w") as temp, \
        open(f"./dir_{interface}/tmp/err_tcpreplay.log", "w") as err:
            try:
                cmd = [
                    "docker", "exec", 
                    f"{name}-container",
                    "tcpreplay",
                    "-i", interface,
                    f"--loop={loop}",
                    f"--mbps={speed}",
                    "/pcap/smallFlows.pcap"
                ]
                # cmd = ["sudo", "tcpreplay", "-i", interface, f"--loop={loop}", f"--mbps={speed}", "./pcap/smallFlows.pcap"]
                tcpreplay_proc[interface] = subprocess.Popen(cmd,stdout=temp, stderr=err)
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
    print("Terminating monitor thread")
    for name in ids_name:
        monitor_threads[name].join()

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
        with open(f"./{name}/perf_files_{pac_size}/drop_rate_{speed}.txt", "w") as f:
            f.write(str(drop_rate[name]))
        with open(f"./{name}/perf_files_{pac_size}/total_packets_{speed}.txt", "w") as f:
            f.write(str(total_packets[name]))

def wait_for_all_drop_rates():
    # Create a function that will wait until err or temp files contain "total packets"
    while open(f"./suricata/tmp/temp.log", 'r').read().find("packets:") < 0 and open(f"./zeek/tmp/err.log", 'r').read().find(f"packets received on interface") < 0 and open(f"./snort/tmp/temp.log", 'r').read().find(f"received:") < 0:
        time.sleep(2)

def create_interface(interfaces):
    for interface in interfaces:
        # Dummy is not enough need to be tunneled interface
        try:
            subprocess.run(["sudo", "ip", "link", "add", interface +"_host", "type", "veth", "peer", "name", interface+"_docker"], check=True)  
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


