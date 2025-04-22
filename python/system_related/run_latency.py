import time
import subprocess
import psutil
import csv
import re
import os
import glob
from scapy.all import IP, TCP, Ether, RandShort, wrpcap
from threading import Thread
from run_all import (
    wait_for_suricata,
    wait_for_snort,
    wait_for_zeek,
    wait_for_suricata_drop_rates,
    wait_for_snort_drop_rates,
    wait_for_zeek_drop_rates,
    extract_drop_rate_snort,
    extract_drop_rate_suricata,
    extract_drop_rate_zeek,
    log_performance,
    restart_interface,
    is_interface_valid,
)
import argparse


def run(ids_name, loop, speed, interface, pcap="smallFlows.pcap"):
    
    folder = "latency"
    latency = pcap.split(".")[0].split("_")[-1].split("us")[0]
    print("LATENCY:",latency)
    speed = latency
    # Fix filepath
    pcap="/pcap/"+pcap
    
    if not os.path.exists(f"./{folder}/{str(ids_name)}/perf_files"):
        print("Directory not found, creating directory...")
        os.makedirs(f"./{folder}/{str(ids_name)}/perf_files")
    filepath = f"./{folder}/{ids_name}/perf_files/ids_performance_log_{latency}.csv"
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
        time.sleep(10)      # TODO: change from sleep to something else - Give the process 10 seconds to intitate.
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
        pcap
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
        # subprocess.run(["docker", "exec", f"{ids_name}-container", "pkill", "-SIGINT", f"{ids_name}"])
        subprocess.run([
            "docker", "exec", f"{ids_name}-container",
            "bash", "-c", f"kill -SIGINT $(pgrep -f {ids_name})"
        ])
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
   
    with open(f"./{folder}/{ids_name}/perf_files/drop_rate_{speed}.txt", "w") as f:
        f.write(str(drop_rate))
    with open(f"./{folder}/{ids_name}/perf_files/total_packets_{speed}.txt", "w") as f:
        f.write(str(total_packets))





def latency_eval(ids_name,loop,speed, interface):
    file_paths = glob.glob("./pcap/latency*")
    print(file_paths)
    for path in file_paths:
        filename = os.path.basename(path)
        print(filename)  # Output: latency_128us.pcap
        print("Running with latency:", filename.split(".")[0].split("_")[-1].split("us")[0])
        run(ids_name, loop, speed, interface, pcap=filename) # Increase loop
        restart_interface(interface.split("_")[0]) # Restart "interface", todo this remove "host" part


def generate_pcap_file_latency_eval(pcap_file_size, throughput_mbps):
    # Latency = TCP Window Size / Throughput
    dst_ip = "192.182.17.2"
    dst_port = 80
    dst_mac = "00:11:22:33:44:55"  # Random mac address

    # Latency test configurations in microseconds
    latency_us_values = [2, 4, 8, 16, 32, 64, 128, 256]  # microseconds

    # Select a fixed throughput for test (in Mbps)
    

    print(f"Using throughput: {throughput_mbps} Mbps")

    # Create pcap directory if it doesn't exist
    os.makedirs("./pcap", exist_ok=True)
    # Check if file of certain pcap len already exists, no need to recreate them
    # TODO: Add a tag or folder inside of pcap that specifies the "pcap_file_size"
    for latency_us in latency_us_values:
        # Calculate required TCP window size in bytes
        window_size_bytes = int((latency_us * throughput_mbps) / 8)
        print(f"\nTarget latency: {latency_us} μs -> Window Size: {window_size_bytes} bytes")

        packets = []  # List to store all packets

        # Create 1000 packets
        for _ in range(pcap_file_size):
            ip = IP(dst=dst_ip)
            tcp = TCP(
                dport=dst_port,
                sport=RandShort(),   # Random source port for variety
                flags='S',           # SYN flag
                window=window_size_bytes
            )
            packet = ip / tcp  # Create the IP/TCP packet
            packets.append(packet)  # Add to packets list
        

        # Wrap all packets in Ethernet frames
        ether_packets = [Ether(dst=dst_mac) / p for p in packets]
        
        # Check number of packets after wrapping
        print(f"Total Ethernet-wrapped packets: {len(ether_packets)}")

        # Define filename for pcap file
        filename = f"latency_{latency_us}us.pcap"
        filename = os.path.join("./pcap/", filename)         
        
        # Save the packets to the pcap file
        wrpcap(filename, ether_packets)
        print(f"✔ Saved {filename} with {len(ether_packets)} packets.")

    print("\nAll files have been saved.")

def main():
    start = time.time()
    """
    Creating an interface:  sudo ip link add veth_host type veth peer name veth_docker
                            sudo ip link set veth_host up
                            sudo ip link set veth_docker up
    """
    print("Current Working Directory:", os.getcwd())
    
    parser = argparse.ArgumentParser(description="Run system performance evaluation on all IDSs with set packet size.")
    parser.add_argument("interface",help="Which interface should the IDSs be run on?")
    args = parser.parse_args()
 
    
    restart_interface(args.interface) # This will create an interface link between interface_name_host and interface_name_docker
    interface = (args.interface+"_host")
    if not is_interface_valid(interface): # Check if interface is valid and exists
        raise Exception(f"Error: interface: {interface} does not exist.")

    loop = 10 # Needs to be increased to a suitable load
    speed = 64 # Must be this value because of formula in Waleed et al
    # Based on speed create accurate pcap files
    # Should be adjustable based on the host computers hardware
    generate_pcap_file_latency_eval(14261,speed) # Generate the files with certain pcap size and speed

    for ids_name in ["snort","zeek","suricata"]:
        latency_eval(ids_name,loop,speed,interface)
        
    
    # visualize()
    runtime = time.time()-start
    print("Runtime:",runtime)
    
    
if __name__ == "__main__":
    main()




