import subprocess
import argparse

def run_suricata(pcap_file):
    """Run Suricata on the provided PCAP file."""
    cmd = ["sudo", "suricata", "-r", pcap_file, "-l", "./logs/suricata"]
    subprocess.run(cmd, check=True)

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Run Suricata on specified PCAP dataset.")
    
    # Add an argument for the dataset
    parser.add_argument(
        "dataset", 
        choices=[
            "TII-SSRC-23", 
            "malicious_http", 
            "normal_traffic"
        ], 
        help="Choose a dataset to run Suricata on"
    )
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Based on the dataset argument, select the correct PCAP file path
    dataset_paths = {
        "bruteforce_ftp": "../dataset_loader/datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_ftp.pcap",
        "malicious_http": "../dataset_loader/datasets/TII-SSRC-23/pcap/malicious/http/http_malicious.pcap",
        "normal_traffic": "../dataset_loader/datasets/TII-SSRC-23/pcap/normal/normal_traffic.pcap"
    }
    
    # Call run_suricata with the selected PCAP file
    pcap_file = dataset_paths[args.dataset]
    run_suricata(pcap_file)

if __name__ == "__main__":
    main()
