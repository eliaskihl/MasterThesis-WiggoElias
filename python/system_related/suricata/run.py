
import time
import subprocess
import time
import psutil
import csv
from threading import Thread

def log_performance(log_file, process_name,tcp_proc):
    # Logs CPU & memory usage of the IDS process every 5 seconds 
    with open(log_file, "w", newline="") as f:
        # Writes to csv
        writer = csv.writer(f)
        writer.writerow(["Time", "CPU_Usage (%)", "Memory_Usage (MB)"])  # CSV header

        while tcp_proc.poll() is None:
            # Find the process by name
            for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_info"]):
                if process_name in proc.info["name"].lower():
                    cpu_usage = proc.info["cpu_percent"]
                    mem_usage = proc.info["memory_info"].rss / (1024 * 1024)  # Convert to MB

                    # Log the data
                    writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cpu_usage, mem_usage])
                    f.flush()  # Ensure immediate write
                    # Print data to console
                    #print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}, CPU: {cpu_usage}%, Memory: {mem_usage}MB")
            time.sleep(5)  # Log every 5 seconds
    print("Logging complete")

def main(loop, speed):
    filepath = "python/system_related/suricata/logs/ids_performance_log.csv"
    # Start Suricata as subprocess
    print("Starting suricata...")
    time.sleep(1)
    temp = open("python/system_related/suricata/tmp/temp_suricata.log", "w")
    err = open("python/system_related/suricata/tmp/err_suricata.log", "w")
    suricata_proc = subprocess.Popen(["sudo", "suricata", "-i", "lo"], stdout=temp, stderr=err)  
    time.sleep(2)
    # Start tcp replay
    print("Starting tcp replay...")
    time.sleep(1)
    temp = open("python/system_related/suricata/tmp/temp_tcpreplay.log", "w")
    err = open("python/system_related/suricata/tmp/err_tcpreplay.log", "w")
    tcpreplay_proc = subprocess.Popen(["sudo", "tcpreplay", "-i", "lo", f"--loop={loop}", f"--mbps={speed}", "/mnt/c/users/it/downloads/text.pcap"],stdout=temp, stderr=err)
    # Log performance in seperate thread while Suricata is running and until tcpreplay is done
    monitor_thread = Thread(target=log_performance, args=(filepath, "suricata", tcpreplay_proc))
    monitor_thread.start()
    time.sleep(1)
    # Wait for Suricata to exit (if manually stopped)
    print("Wait for TCP replay to finish")
    tcpreplay_proc.wait()
    
    time.sleep(2)
    print("Wait for suricata to finish")
    suricata_proc.wait()
    time.sleep(1)
    print("Termating suricata..")
    suricata_proc.terminate()
    
    # End / join thread
    print("Terminating monitor thread")
    monitor_thread.join()



main(100,100)