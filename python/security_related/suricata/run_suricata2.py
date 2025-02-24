import os
import subprocess

# write message to console and expect user input
def prompt_user(message):
    print(message)
    return input()

dataset = prompt_user("Choose dataset to run Suricata on: \n - UNSW-NB15 \n- *TII_SSRC_23")

if dataset == "UNSW-NB15":
    exec(open("python/security_related/suricata/UNSW_NB15.py").read())