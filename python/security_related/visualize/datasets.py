import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

data = {
    "Metric": ["HTTP Bruteforce", "SSH Bruteforce", "Mirai Scan Bruteforce"],
    "Suricata": [0.4029, 0, 0.0174],
    "Snort": [0.5271, 0.4918, 0.001],
    "Zeek": [0, 0, 0.0372],
}

df = pd.DataFrame(data)

# Convert to percentage
df["Suricata"] = df["Suricata"] * 100
df["Snort"] = df["Snort"] * 100
df["Zeek"] = df["Zeek"] * 100

indices = np.arange(len(df["Metric"]))
bar_width = 0.25

# Plot bars
plt.bar(indices - bar_width, df["Suricata"], width=bar_width, label="Suricata")
plt.bar(indices, df["Snort"], width=bar_width, label="Snort")
plt.bar(indices + bar_width, df["Zeek"], width=bar_width, label="Zeek")

# Labeling
plt.xlabel("Attack")
plt.ylabel("Accuracy (%)")
plt.xticks(indices, df["Metric"], rotation=90)
plt.yticks(np.arange(0, 110, 10))  # Set y-axis ticks at 10% intervals
plt.title("Accuracy for NIDS running on TII-SSRC-23 dataset")
plt.legend()
plt.tight_layout()
plt.show()
# Save figure
# plt.savefig("img/nids_fpr_by_attack.png")
