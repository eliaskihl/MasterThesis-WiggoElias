
import time
import subprocess
import time
import psutil
import csv
import sys
from threading import Thread
from suricata.vis_csv import visualize

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

def run(ids_name, loop, speed):
    # TODO: Add a sudo su command for root access

    filepath = f"python/system_related/{ids_name}/logs/ids_performance_log_{speed}.csv"
    # Start {ids_name} as subprocess
    print_log(f"Starting {ids_name}...")
    time.sleep(1)
    temp = open(f"python/system_related/{ids_name}/tmp/temp_{ids_name}.log", "w")
    err = open(f"python/system_related/{ids_name}/tmp/err_{ids_name}.log", "w")
    ## DEPENDING ON IDS USE DIFFERENT COMMANDS
    if ids_name == "suricata":
        ids_proc = subprocess.Popen(["sudo", f"{ids_name}", "-i", "eth0"], stdout=temp, stderr=err) 
    elif ids_name == "snort":
        ids_proc = subprocess.Popen(["sudo", f"{ids_name}", "-v", "-i", "eth0"], stdout=temp, stderr=err)
    elif ids_name == "zeek":
        ids_proc = subprocess.Popen(["sudo", f"{ids_name}", "-i", "eth0", "-C", "zeek_init.cfg"], stdout=temp, stderr=err)
    time.sleep(2)
    # Start tcp replay
    print_log("Starting tcp replay...")
    time.sleep(1)
    temp = open(f"python/system_related/{ids_name}/tmp/temp_tcpreplay.log", "w")
    err = open(f"python/system_related/{ids_name}/tmp/err_tcpreplay.log", "w")
    tcpreplay_proc = subprocess.Popen(["sudo", "tcpreplay", "-i", "eth0", f"--loop={loop}", f"--mbps={speed}", "python/system_related/pcap/bigFlows.pcap"],stdout=temp, stderr=err)
    # Log performance in seperate thread while {ids_name} is running and until tcpreplay is done
    monitor_thread = Thread(target=log_performance, args=(filepath, "{ids_name}", tcpreplay_proc))
    monitor_thread.start()
    time.sleep(1)
    # Wait for {ids_name} to exit (if manually stopped)
    print_log("Wait for TCP replay to finish")
    tcpreplay_proc.wait()
    time.sleep(1)
    print_log(f"Terminating tcpreplay..")
    tcpreplay_proc.terminate()
    time.sleep(2)
    print_log(f"Wait for {ids_name} to finish")
    ids_proc.wait()
    time.sleep(1)
    print_log(f"Termating {ids_name}..")
    ids_proc.terminate()
    
    # End / join thread
    print_log("Terminating monitor thread")
    monitor_thread.join()



def main(ids_name):
    for i in range(10, 150, 20):
        print("Running with speed:", i)
        run(1,i)
    visualize(f"{ids_name}")
    
    
main()