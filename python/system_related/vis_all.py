import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
from suricata.vis_csv import calc_mean
def visualize():



    speeds = []
    cpus = []
    mems = []
    drop_rates = []
    # Create empty dataframe
    dfs = {}
    size = 512
    for name in ["suricata","snort3","zeek"]:
        sur_files = glob.glob(f"python/system_related/{name}/perf_files_{size}/ids_performance_log*.csv")
       
        for file in sur_files:
            print(file)
            speed =(int(file.split("_")[-1].split(".")[0]))
            speeds.append(speed)
            cpu, mem = calc_mean(file)
            cpus.append(cpu)
            mems.append(mem)
            # TODO: Check if file exists before reading
            with open(f"python/system_related/{name}/perf_files/drop_rate_{speed}.txt", "r") as f:
               drop_rate = float(f.read())
               drop_rates.append(drop_rate)
        dfs[name] = pd.DataFrame({"Speed":speeds, "CPU":cpus, "Memory":mems, "Drop Rate":drop_rates})
        # Clear
        speeds = []
        cpus = []
        mems = []
        drop_rates = []

    df_sur = dfs["suricata"]
    df_snort = dfs["snort3"]
    df_zeek = dfs["zeek"]
    print(df_sur)
    print(df_snort)
    print(df_zeek)
    # Merge based on "Speed"
    df = pd.merge(df_sur, df_snort, on="Speed", suffixes=('_suricata', '_snort3'))
    print(df)
    print("")
    df = pd.merge(df_zeek, df, on="Speed", suffixes=('_zeek', ''))
    print(df)
    # Change name of column "CPU" to "CPU_zeek"
    df.rename(columns={"CPU":"CPU_zeek", "Memory":"Memory_zeek", "Drop Rate":"Drop Rate_zeek"}, inplace=True)
    print(df)
    
    
    width,height = 8,6
    df.plot(x="Speed", y=["CPU_suricata", "CPU_snort3","CPU_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title(f"CPU Usage Packet Size: {size}")
    plt.ylabel("CPU (%)")
    print("Saving plot CPU")
    plt.savefig(f"img/cpu.png")

    df.plot(x="Speed", y=["Memory_suricata", "Memory_snort3","Memory_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title(f"Memory Usage Packet Size: {size}")
    plt.ylabel("Memory (%)")
    print("Saving plot Memory")
    plt.savefig(f"img/memory.png")
    
    df.plot(x="Speed", y=["Drop Rate_suricata", "Drop Rate_snort3","Drop Rate_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title(f"Drop Rate Packet Size: {size}")
    plt.ylabel("Drop Rate (%)")
    print("Saving plot Drop Rate")
    plt.savefig(f"img/drop_rate.png")


#visualize()