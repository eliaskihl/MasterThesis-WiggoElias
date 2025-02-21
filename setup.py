import os 
import subprocess
from pathlib import Path



ROOT_DIR = Path(__file__).resolve().parent

def install_dependencies() -> None:
    """Install dependencies from requirements.txt."""
    requirements_file = ROOT_DIR / "requirements.txt"
    print(f"Installing dependencies from {requirements_file}...")
    subprocess.run(["pip", "install", "-r", str(requirements_file)], check=True)
