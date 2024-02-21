import subprocess

# List of tuples containing filename and output dir
t = [
    ('/home/alya/Desktop/StratosphereLinuxIPS/Dataset/2023-02-20-00-00-03-192.168.1.109.pcap', '/home/alya/Desktop/IDPS-Comparison-Tool/dataset/2023-02-20/2023-02-20/slips'),
    ('~/Desktop/IDPS-Comparison-Tool/dataset/Experiment-VM-Linux-Ubuntu2204-1-2023-02-25/2023-02-25-00-01-53-192.168.1.109.pcap', '/home/alya/Desktop/IDPS-Comparison-Tool/dataset/Experiment-VM-Linux-Ubuntu2204-1-2023-02-25/slips'),
    ('~/Desktop/StratosphereLinuxIPS/Dataset/CTU-Malware-Capture-Botnet-4/2013-08-20_capture-win5.pcap', '/home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/slips'),
    ('/home/alya/Desktop/IDPS-Comparison-Tool/dataset/Experiment-VM-Microsoft-Windows7AD-1-2023-02-26/2023-02-26-00-01-48-192.168.1.108.pcap', '/home/alya/Desktop/IDPS-Comparison-Tool/dataset/Experiment-VM-Microsoft-Windows7AD-1-2023-02-26/slips')
]

# Loop through the list of tuples and run the command for each tuple
for tpl in t:
    command = f"./slips.py -e 1 -f {tpl[0]} -o {tpl[1]}"
    print(f"running {command}")
    subprocess.run(command, shell=True, cwd="/home/alya/Desktop/StratosphereLinuxIPS")

# Optional: Print a message when the loop is finished
print("Commands executed successfully.")
