import os
import subprocess
from UNSW_NB15 import main

def run_suricata(dataset,path_to_pcap_files):
    """Run Suricata on the provided PCAP files."""
    outputdir =  os.path.abspath(f"python/security_related/datasets/{dataset}/eve_files")
    cmd = ["sudo", "suricata", "-r", path_to_pcap_files, "-l", outputdir , "--runmode=workers"]
 # Hardcoded path to dir?
    subprocess.run(cmd, check=True)

# write message to console and expect user input
def prompt_user(message):
    print(message)
    return input()

dataset = prompt_user("Choose dataset to run Suricata on: \n [1] - UNSW-NB15 \n [2] - TII_SSRC_23")

if dataset == "1":
    path_to_output = f"python/security_related/datasets/{dataset}/eve_files"
    # Run Suricata on the UNSW-NB15 dataset
    # Run suricata on the directory of the pcap file should return the path to the directory of the eve files
    path_to_input = prompt_user("Where is you pcap files located?") # Needs to be in format /path/to/pcapfiles/1...10/*.pcap
    # serach the directory for the pcap files and send the path to the run_suricata function
    print(path_to_input)
    run_suricata(dataset,path_to_input)
    main(path_to_output)


