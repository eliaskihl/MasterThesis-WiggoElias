import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
from suricata.vis_csv import calc_mean
def visualize():



    speeds = []
    cpus = []
    mems = []
    # Create empty dataframe
    dfs = {}
    for name in ["suricata","snort3","zeek"]:
        sur_files = glob.glob(f"python/system_related/{name}/perf_files/ids_performance_log*.csv")
       
        for file in sur_files:
            print(file)
            speeds.append((int(file.split("_")[-1].split(".")[0])))
            cpu, mem = calc_mean(file)
            cpus.append(cpu)
            mems.append(mem)  
        dfs[name] = pd.DataFrame({"Speed":speeds, "CPU":cpus, "Memory":mems})
        # Clear
        speeds = []
        cpus = []
        mems = []

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
    df.rename(columns={"CPU":"CPU_zeek", "Memory":"Memory_zeek"}, inplace=True)
    print(df)
    
    
    width,height = 8,6
    df.plot(x="Speed", y=["CPU_suricata", "CPU_snort3","CPU_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title("CPU Usage")
    plt.ylabel("CPU (%)")
    print("Saving plot CPU")
    plt.savefig(f"img/cpu.png")

    df.plot(x="Speed", y=["Memory_suricata", "Memory_snort3","Memory_zeek"], kind="bar", figsize=(width,height), label=["Suricata", "Snort3", "Zeek"])
    plt.title("Memory Usage")
    plt.ylabel("Memory (%)")
    print("Saving plot Memory")
    plt.savefig(f"img/memory.png")


visualize()