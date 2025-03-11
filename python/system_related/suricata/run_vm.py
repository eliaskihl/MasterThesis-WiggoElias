# use vmrun.exe

# Instead of calling vmrun.exe to start the program, you can configure the VM to automatically run a script on startup

# vmrun copyFileFromGuestToHost

#CHATGPT: To start vm
import subprocess

# Path to vmrun executable (adjust based on your OS and VMware version)
VMRUN_PATH = "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe"
VMX_PATH = "C:\\path\\to\\your\\vm.vmx"  # Path to your VM's .vmx file

def start_vm():
    try:
        subprocess.run([VMRUN_PATH, "start", VMX_PATH, "nogui"], check=True)
        print("VM started successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error starting VM: {e}")

if __name__ == "__main__":
    start_vm()
