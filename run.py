import subprocess
import argparse
import os

# Mapping of tool names to their respective directories and scripts
TOOLS = {
    "suricata": {
        "dir": "python/security_related/suricata",
        "script": "run_suricata.py",
    },
        "zeek": {
        "dir": "python/security_related/zeek",
        "script": "run_zeek.py",
    }
}

parser = argparse.ArgumentParser(description="Run specified security tools from the root directory")
parser.add_argument("tool", help="Name of the tool to run (e.g., suricata)")
parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to pass to the tool")

args = parser.parse_args()

if args.tool not in TOOLS:
    print(f"Error: Unknown tool '{args.tool}'. Available tools: {', '.join(TOOLS.keys())}")
    exit(1)

tool_info = TOOLS[args.tool]
nested_dir = tool_info["dir"]
script = tool_info["script"]

command = ["python", script] + args.args 

subprocess.run(command, cwd=nested_dir)
