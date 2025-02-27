
import time
import subprocess
import time
import psutil
import csv
import sys
from threading import Thread
from vis_csv import visualize

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
                    # temp arrays
                    # mem = []
                    # cpu = []
                    # # save process id
                    # list_of_pids = []
                    # first_run = True
                    # if proc.info["pid"] not in list_of_pids and first_run:
                    #     print("adding to pid list")
                    #     list_of_pids.append(proc.info["pid"])
                    #     # just add 
                    # elif proc.info["pid"] in list_of_pids and proc.info["pid"] == list_of_pids[0] and first_run:
                    #     first_run = False
                    #     memory_percentage = sum(mem)
                    #     cpu_usage = sum(cpu)
                    #     mem = []
                    #     cpu = []
                    #     writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cpu_usage, memory_percentage])
                    #     f.flush()
                
                    cpu_usage = proc.info["cpu_percent"]
                    rss_mem = proc.info["memory_info"].rss # rss mem in bytes?
                    # Get the total system memory (in bytes)
                    tot_mem = psutil.virtual_memory().total
                    memory_percentage = (rss_mem / tot_mem) * 100

                    # if proc.info["pid"] == list_of_pids[-1] and not first_run:
                    #     print("writing to csv")
                    #     mem.append(memory_percentage)
                    #     cpu.append(cpu_usage)
                    #     memory_percentage = sum(mem)
                    #     cpu_usage = sum(cpu)
                    #     mem = []
                    #     cpu = []
                    #     writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cpu_usage, memory_percentage])
                    #     f.flush()
                    # else:  
                    #     print("appending to temp arrays")
                    #     mem.append(memory_percentage)
                    #     cpu.append(cpu_usage)
                    writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cpu_usage, memory_percentage])
                    f.flush()

                    print(proc.info["name"], ":", proc.info["cpu_percent"],":", memory_percentage, ":", proc.info["pid"])

            time.sleep(5)
            #psutil.process_iter.cache_clear()
    print_log("Logging complete")

def run(loop, speed):
    # TODO: Add a sudo su command for root access

    filepath = f"python/system_related/suricata/logs/ids_performance_log_{speed}.csv"
    # Start Suricata as subprocess
    print_log("Starting suricata...")
    time.sleep(1)
    temp = open("python/system_related/suricata/tmp/temp_suricata.log", "w")
    err = open("python/system_related/suricata/tmp/err_suricata.log", "w")
    suricata_proc = subprocess.Popen(["sudo", "suricata", "-i", "eth0"], stdout=temp, stderr=err)  
    time.sleep(2)
    # Start tcp replay
    print_log("Starting tcp replay...")
    time.sleep(1)
    temp = open("python/system_related/suricata/tmp/temp_tcpreplay.log", "w")
    err = open("python/system_related/suricata/tmp/err_tcpreplay.log", "w")
    tcpreplay_proc = subprocess.Popen(["sudo", "tcpreplay", "-i", "lo", f"--loop={loop}", f"--mbps={speed}", "python/system_related/pcap/bigFlows.pcap"],stdout=temp, stderr=err)
    # Log performance in seperate thread while Suricata is running and until tcpreplay is done
    monitor_thread = Thread(target=log_performance, args=(filepath, "suricata", tcpreplay_proc))
    monitor_thread.start()
    time.sleep(1)
    # Wait for Suricata to exit (if manually stopped)
    print_log("Wait for TCP replay to finish")
    tcpreplay_proc.wait()
    time.sleep(1)
    print_log("Terminating tcpreplay..")
    tcpreplay_proc.terminate()
    time.sleep(2)
    print_log("Wait for suricata to finish")
    suricata_proc.wait()
    time.sleep(1)
    print_log("Termating suricata..")
    suricata_proc.terminate()
    
    # End / join thread
    print_log("Terminating monitor thread")
    monitor_thread.join()



def main():
    for i in range(10, 150, 20):
        print("Running with speed:", i)
        run(1,i)
    visualize("Suricata")
    
    
main()