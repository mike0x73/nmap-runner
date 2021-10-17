#!/usr/bin/env python3

import subprocess
import datetime
import os
import threading
import time
import signal

def timer(time_to_kill):
    while datetime.datetime.now() < time_to_kill:
        time.sleep(5)
    print("Time to stop")
    # Kill process due to multithreaded
    pid = os.getpid()
    os.kill(pid, signal.SIGTERM)

def get_alive_hosts(location):
    results = []
    with open(location + ".gnmap", 'r') as file:
        lines = file.readlines()
        for line in lines:
            if "Status: Up" in line:
                results.append(line.split(' ')[1]) 
    return results

def write_lines(location, lines):
    with open(location, 'w') as file:
        for line in lines:
            file.write(line + "\n")

if not os.geteuid() == 0:
    print("Run me as root!")
    exit(1)

####################################################
# CONFIG

subnets_ips = ["192.168.1.50/28"]
start = "04-07-2021 17:38:00"
end = "04-07-2022 17:39:00"

####################################################

start_time = datetime.datetime.strptime(start, "%d-%m-%Y %H:%M:%S")
end_time = datetime.datetime.strptime(end, "%d-%m-%Y %H:%M:%S")

while datetime.datetime.now() < start_time:
    time.sleep(5)

th = threading.Thread(target=timer, args=(end_time,))
th.start()

if not os.path.isdir("nmap"):
    os.mkdir("nmap")
if not os.path.isdir("nmap/hosts"):
    os.mkdir("nmap/hosts")
if not os.path.isdir("nmap/ports"):
    os.mkdir("nmap/ports")
if not os.path.isdir("nmap/debug"):
    os.mkdir("nmap/debug")
if not os.path.isdir("nmap/services"):
    os.mkdir("nmap/services")
if not os.path.isdir("nmap/udp"):
    os.mkdir("nmap/udp")

for target in subnets_ips:
    try:
        # get responsive hosts 
        store_location = "nmap/hosts/" + target.replace("/", "-")
        subprocess.run(["nmap", "-sn", "-oA", store_location, "-v", target])
        alive_hosts = get_alive_hosts(store_location)

        alive_hosts_file = "nmap/debug/" + target.replace("/", "-") + ".parsed.txt"
        write_lines(alive_hosts_file, alive_hosts)

        # get open ports on hosts
        store_location = "nmap/ports/" + target.replace("/", "-")

        open_ports = []
        cmd = ["nmap", "-Pn", "-p-", "-oA", store_location, "-v", "-iL", alive_hosts_file]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in iter(p.stdout.readline, b''):
            decoded_line = line.decode().rstrip()
            print(decoded_line)
            if "Discovered open port" in decoded_line:
                port = decoded_line.split(' ')[3].split('/')[0]
                if port not in open_ports:
                    open_ports.append(port)
        ports_to_scan = ','.join(open_ports)

        # Run service enum scan
        store_location = "nmap/services/" + target.replace("/", "-")
        subprocess.run(["nmap", "-Pn", "-sV", "-p", ports_to_scan, "-oA", store_location, "-v", "-iL", alive_hosts_file])

        # UDP scan
        store_location = "nmap/udp/" + target.replace("/", "-")
        subprocess.run(["nmap", "-Pn", "-sU", "--top-ports=20", "-oA", store_location, "-v", "-iL", alive_hosts_file])

        print("\n##### Completed scan of " + target + " #####\n")

    except Exception as ex:
        print("Error scanning " + target + ": " + str(ex))

print ("Program Finished")

# Kill process due to multithreaded
pid = os.getpid()
os.kill(pid, signal.SIGTERM)