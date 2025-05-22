import psutil
import time
import os
import csv

def monitor_system(interval=1):
    log_file = "./logs.txt"
    
    with open(log_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "CPU_Usage (%)", "Memory_Usage (%)"])  # CSV header
        while True:
            # CPU usage (percentage of total across all cores)
            cpu_percent = psutil.cpu_percent(interval=interval)
            
            # Memory usage
            memory = psutil.virtual_memory()
            mem_percent = memory.percent
            mem_used = memory.used / (1024 ** 3)  # Convert bytes to GB
            mem_total = memory.total / (1024 ** 3)

            print(f"CPU Usage: {cpu_percent}%")
            print(f"Memory Usage: {mem_percent}% ({mem_used:.2f} GB / {mem_total:.2f} GB)")
            print("-" * 40)
            writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), cpu_percent, mem_percent])
            f.flush()
# Run the monitor
monitor_system()
