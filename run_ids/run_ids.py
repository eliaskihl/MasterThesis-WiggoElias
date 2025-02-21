import subprocess

def run_suricata(pcap_file):
    """Run Suricata on the provided PCAP file."""
    cmd = ["sudo", "suricata", "-r", pcap_file, "-l", "../logs/suricata"]
    subprocess.run(cmd, check=True)

if __name__ == "__main__":
    run_suricata("../dataset_loader/datasets/TII-SSRC-23/pcap/malicious/bruteforce/bruteforce_ftp.pcap")
