import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
from suricata.vis_csv import calc_mean
def visualize():


    # Suricata
    speeds = []
    cpus = []
    mems = []
    names = []
    # create empty dataframe
    dfs = {}
    for name in ["suricata","snort3"]:
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
    print(df_sur)
    print(df_snort)

    # Merge based on "Speed"
    df = pd.merge(df_sur, df_snort, on="Speed", suffixes=('_suricata', '_snort3'))
    print(df)

    
    # df_sur = df[df["Name"] == "suricata"]
    # df_snort = df[df["Name"] == "snort3"]
    # # Plot CPU and Memory usage bars
    # fig, axes = plt.subplots(2, 1, figsize=(10, 5))
    # x = np.arange(len(df['Speed']))
    # # CPU Usage Bar Plot
    # axes[0].bar(df['Speed'].astype(str), df_sur['CPU'], color='orange', width=0.8,label="Suricata")
    # axes[0].bar(df['Speed'].astype(str), df_snort['CPU'], color='blue', width=0.8, label="Snort3")
    # axes[0].set_title('CPU Usage')
    # axes[0].set_ylabel('CPU (%)')
    # axes[0].set_xticks(x)
    # axes[0].set_xticklabels(df['Speed'])
    # axes[0].legend()
    # # Memory Usage Bar Plot
    # axes[1].bar(df['Speed'].astype(str), df_snort['Memory'], color='blue', width=0.8,label="Snort3")
    # axes[1].bar(df['Speed'].astype(str), df_sur['Memory'], color='orange', width=0.8,label="Suricata")
    # axes[1].legend()
    # axes[1].set_title('Memory Usage')
    # axes[1].set_ylabel('Memory (%)')
    # axes[1].set_xticklabels(df['Speed'].astype(str))
    # # Adjust layout for closer bars
    # plt.subplots_adjust(wspace=0.1)
    # # Show the plots
    # plt.tight_layout()
    width,height = 8,6
    df.plot(x="Speed", y=["CPU_suricata", "CPU_snort3"], kind="bar", figsize=(width,height))
    plt.title("CPU Usage")
    plt.ylabel("CPU (%)")
    print("Saving plot CPU")
    plt.savefig(f"img/cpu.png")

    df.plot(x="Speed", y=["Memory_suricata", "Memory_snort3"], kind="bar", figsize=(width,height))
    plt.title("Memory Usage")
    plt.ylabel("Memory (%)")
    print("Saving plot Memory")
    plt.savefig(f"img/memory.png")


visualize()