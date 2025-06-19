# NIDS evaluation framework

A framework that allows you to evaluate the three open-source NIDS: Snort, Suricata and Zeek, as well as the cluster management tool, ZeekControl (ZeekCtl) based on relevant metrics. 

## Introduction
The purpose of this framework is to provide a testing environment to deploy and evaluate the NIDS candidates mentioned above. The framework consists of three modules:

**Classification Performance Module:**
Provides a way to test the NIDS candidates on benign and malicious traffic from four relevant datasets and a traffic generator. This module includes the datasets: UNSW-NB15, CIC-IDS2017, BOT-IOT and TII-SSRC-23 as well as the traffic generator: ID2T.

**System Performance Module:** 
Allows for stress-testing the NIDS candidates with network traffic with varying throughputs and latencies. 

**Controller Performance Module:**
Which tests the cluster management tool ZeekCtl on relevant metrics related to different aspects. 
# Prerequisites 
Python and Docker installed on the system.

# Installation
To set up the project and install the dependencies follow these steps:
##  Step 1: Clone the Repository
Clone the project repository to your local machine using the following command:
(update this with our public github repo)

```bash
git clone https://github.com/eliaskihl/MasterThesis-WiggoElias.git 
```
## Step 2: Navigate to the Project Directory
Navigate to the root directory of the cloned repository.
```bash
cd MasterThesis-WiggoElias
```
## Step 3: Download datasets
Download the packet trace (PCAP) files from the datasets and place them in the correct folders in **./python/security_related/datasets**. The corresponding zip-files also have to be downloaded. To perform key setup steps like installing the required dependencies, run the following command:  

```bash
python setup.py
```

## Step 5: Deploy docker containers

To build and start the docker containers containing  the NIDS candidates, run the following script:

```bash
./start.sh
```

After the docker containers are successfully build the framework is now ready to be used. 

## Usage
This is how to run the framework from the source of the project: 

**Classification Performance Module:**

This module can be run with either parts or the whole of the datasets:

To run a single PCAP file from a dataset, this command can be issued: 
```bash
python run.py -tool snort -dataset UNSW-NB15 -pcap pcaps_17-2-2015/1.pcap
```
To run a single attack from the traffic generator, this command can be issued:   
```bash
python run.py -tool snort -traffic_generator ID2T -attack EternalBlueExploit
```

The Classification Performance Module can also be run with all datasets and attacks from the ID2T traffic generator with the use of this command (note that the specific pcap files can be changed in run.py): 
```bash
python run.py -tool datasets_traffic_generators
```
What datasets packet trace files and traffic generator attacks that are to be included in this command can be changed in the *DATASETS* and *TRAFFIC_GENERATORS* dictionaries in the run.py file in the source of the project.  

**System Performance Module:**

There are diffferent commands to stress-test the different NIDS.

To expose the NIDS to network traffic at different throughputs ranging from 10 to 100 Mbps with 10 Mbps steps, the following command can be issued:
```bash
python run.py -tool throughput -i veth -loop 10 -b 10 -e 101 -s 10
```
To expose the NIDS to network traffic at different latencies, the following command can be issued:
```bash
python run.py -tool latency -i veth -speed 8 -loop 1
```

**Controller Performance Module:**

To test the cluster management tool ZeekCtl, the following command can be issued to set up a cluster with 2 workers, 1 logger, 1 manager and feed the system with throughputs ranging from 10 to 100 Mbps with 10 Mbps steps   
```bash
python run.py --tool controller -i veth -loop 10 -b 10 -e 101 -s 10 -worker 2 -logger 1 -manager 1 -proxy 1
```

**Compilation of all metrics**

To collect all the metrics produced from the different modules, the following command can be issued to collect them into a table csv file which will be placed in **./tables**

