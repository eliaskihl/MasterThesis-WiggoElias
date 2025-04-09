import os 
import subprocess
from pathlib import Path
import zipfile

ROOT_DIR = Path(__file__).resolve().parent

def install_dependencies() -> None:
    """Install dependencies from requirements.txt."""
    requirements_file = ROOT_DIR / "requirements.txt"
    print(f"Installing dependencies from {requirements_file}...")
    subprocess.run(["pip", "install", "-r", str(requirements_file)], check=True)


def extract_groundtruth(zip_dirs):
    for zip_dir in zip_dirs:
        for filename in os.listdir(zip_dir):
            if filename.endswith(".zip"):
                zip_path = os.path.join(zip_dir, filename)
                extract_path = zip_dir  # Extract directly into the same folder

                print(f"Extracting {filename} into {extract_path}...")
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                print(f"Extracted {filename}")
                os.remove(zip_path)

if __name__ == "__main__":
    zip_directories = [
    "./python/security_related/datasets/BOT-IOT/ground_truth",
    "./python/security_related/datasets/CIC-IDS2017/ground_truth",
    "./python/security_related/datasets/TII-SSRC-23/ground_truth",
    "./python/security_related/datasets/UNSW-NB15/ground_truth"
    ]
    extract_groundtruth(zip_directories)
