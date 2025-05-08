import subprocess
from pathlib import Path

def merge_pcaps_in_folder(folder):
    folder_path = Path(folder)
    pcap_files = sorted(folder_path.glob('*.pcap'))

    if not pcap_files:
        print(f"No PCAP files found in {folder_path}")
        return

    merged_pcaps = folder_path / f"{folder_path.name}_merged_pcaps.pcap"
    merged_ether = folder_path / f"{folder_path.name}.pcap"

    # Merge PCAPs
    print(f"Merging PCAPs in {folder_path}...")
    mergecap_cmd = ['mergecap', '-F', 'pcap', '-w', str(merged_pcaps)] + [str(p) for p in pcap_files]
    subprocess.run(mergecap_cmd, check=True)
    print(f"Saved merged PCAP to {merged_pcaps}")

    # Convert to Ethernet format so that snort can process.
    print(f"Converting {merged_pcaps.name} to Ethernet format...")
    editcap_cmd = ['editcap', '-T', 'ether', '-L', '-C', '12:2', str(merged_pcaps), str(merged_ether)]
    subprocess.run(editcap_cmd, check=True)
    print(f"Saved converted PCAP to {merged_ether}")
    
    print(f"Removing intermediate file {merged_pcaps}")
    merged_pcaps.unlink()

def main():
    script_dir = Path(__file__).parent
    folders_to_process = ['pcaps_22-1-2015', 'pcaps_17-2-2015']

    for folder_name in folders_to_process:
        folder = script_dir / folder_name
        if folder.exists():
            merge_pcaps_in_folder(folder)
        else:
            print(f"Folder {folder} does not exist!")

if __name__ == '__main__':
    main()
