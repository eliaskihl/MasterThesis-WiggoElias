# Process for running the program ###
##### Must be run in WSL or Linux
### Step 1
Have a folder with pcap files for a dataset that is given in the program (UNSW-NB15, TI-SSRC-23, etc)
### Step 2
Select which IDS/ to use
Run from the source directory with 'python run.py *ids* *dataset* *pcap-file or folder*
### Step 3
When running an IDS it will ask you to give the path of the pcap folder
### Step 4
Program runs file and returns a confusion matrix (add ROC curve)
### Step 5
VM starts and is initialized with set intrusctions 
### Step 6
Benign traffig generation will flow over the network on a set interface 
### Step 7
System monitoring tool will mointor and save a log in a given path
### Step 8
This log will be vizualized with python script that runs after the VM session is completed
### Step 9
Display more graphs