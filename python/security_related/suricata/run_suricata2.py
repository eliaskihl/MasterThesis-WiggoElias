import os
import subprocess
from UNSW_NB15 import main
import glob
 
def run_suricata(dataset, path_to_pcap_file,path_to_output): 
    """Run Suricata on the provided PCAP files."""    
    cmd = ["sudo","suricata", "-r", path_to_pcap_file, "-l", path_to_output]
    subprocess.run(cmd, check=True)

# write message to console and expect user input
def prompt_user(message):
    print(message)
    return input()



# MAIN PROMPT
dataset = prompt_user("Choose dataset to run Suricata on: \n [1] - UNSW-NB15 \n [2] - TII_SSRC_23")
if dataset == "1": # UNSW-NB15
    dataset = "UNSW-NB15"
    path_to_input = prompt_user("Where is you pcap files located?") # Needs to be in format /path/to/pcapfiles/1...10/*.pcap
    path_to_input = os.path.normpath(path_to_input)  # Normalize Windows path to avoid issues

    # Search the given directory in "path_to_input" for all pcap files
    file_path = os.path.join(path_to_input, "*.pcap")
    
    files = glob.glob(file_path)
    for file in files:
        # extract name of pcap file in "file"
        x = file.split("/")[-1]
        x = x.split(".")[0]
        path_to_output = os.path.join("python", "security_related", "suricata", "logs", x)
        print(file)
        os.mkdir(path_to_output)
        run_suricata(dataset,file,(x+1),path_to_output)
    output_path = os.path.join("python", "security_related", "suricata", "logs") # Specifially for UNSW-NB15
    print(f"{len(files)} PCAP files processed into JSON files...")
    main(output_path)

#/mnt/c/Users/It/Downloads/