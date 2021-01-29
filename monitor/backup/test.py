import os
import sys
import time
import struct
import socket
import atexit
import subprocess

basePath = "/home/zl/runsc/monitor/"
kernelPath = basePath + "kernel"
log = basePath + "log/targetAddrs.list"

def get_pid():
    targets = []
    cmd = "ps -aux | grep nobody | grep exe | grep -v grep"
    res = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
    result = res.stdout.readlines()

    max_cpu = 0.0
    target_pid = "-1"
    for line in result:
        line = ' '.join(str(line).split())

        items = str(line).split(" ")

        pid = items[1]
        rss = items[5]
        time = items[9]
        cpu = items[2]
        mem = items[3]

        if mem != "0.0" or cpu != "0.0" or time != "0:00":
            #targets.append(pid)
            if float(cpu) > max_cpu:
                max_cpu = float(cpu)
                target_pid = pid
    
    if target_pid != "-1":
        return [target_pid]

    return targets

def exit_handler():
    os.system("rmmod daptrace")

def chk_prerequisites():
    if os.geteuid() != 0:
        print "Run as root"
        exit(1)

    if os.path.isfile(log):
        os.rename(log, log + ".old")

    #atexit.register(exit_handler)

    if not os.path.isdir(DBGFS):
        #dprint("Buildling daptrace kernel module..")
        #os.system("cd %s && make" % kernelPath) 
        
        #print("Inserting daptrace kernel module..")
        os.system("cd %s && insmod daptrace.ko" % kernelPath)

    if not os.path.isfile(DBGFS_PIDS):
        print("[Error] mapia pids file (%s) not exists." % DBGFS_PIDS)
        exit(1)

"""
def analyze_log():
    if os.path.exists(log) == False:
        print("[Error] log file not exists.")
        return

    with open(log, 'rb') as f:
        #for line in lines:
        flag = 0
        while True:
            try:
                line = f.read(8)
                flag = 1
                addr = struct.unpack('L', line)[0]
                if addr != 0:
                    address = hex(addr)
                    #print (address)
                    return address
                else:
                    print ("[Error] addr is 0.")
                    exit(1)
            except:
                print("[Error] read failed.")
                exit(1)
"""

def analyze_log():
    if os.path.exists(log) == False:
        print("[Error] log file not exists.")
        return

    with open(log, 'rb') as f:
        #for line in lines:
        flag = 0
        while True:
            try:
                line = f.read(8)
                flag = 1
                addr = struct.unpack('L', line)[0]

                print ("test ", addr)

                line = f.read(8)
                access = struct.unpack('L', line)[0]

                #access
                line = f.read(8)
                access = struct.unpack('L', line)[0]

                if addr != 0:
                    address = hex(addr)
                    access = int(access)
                    #print (address, access)
                    return address, access
                else:
                    print ("[Error] addr is 0.")
                    exit(1)
            except:
                print("[Error] read failed.")
                exit(1)


DBGFS="/sys/kernel/debug/mapia/"
DBGFS_ATTRS = DBGFS + "attrs"
DBGFS_PIDS = DBGFS + "pids"
DBGFS_TRACING_ON = DBGFS + "tracing_on"

def get_target_addr():
    targets = [sys.argv[1]]
    if len(targets) == 0:
        print ("[Error] don't have targets")
        return

    # strat kernel module
    for pid in targets:
        chk_prerequisites()
        #print("Start tracing...")

        subprocess.call("echo %s > %s" % (pid, DBGFS_PIDS),
                shell=True, executable="/bin/bash")
        subprocess.call("echo on > %s" % DBGFS_TRACING_ON,
                shell=True, executable="/bin/bash")
        time.sleep(0.1)
        subprocess.call("echo off > %s" % DBGFS_TRACING_ON,
                shell=True, executable="/bin/bash")
        
        #subprocess.call("echo %s > %s" % (orig_attrs, DBGFS_ATTRS), shell=True,
        #        executable="/bin/bash")
        
        #print("Tracing done.")

        # make sure the log file exists
        exit_handler()

        # get the target addr
        addr, access = analyze_log()

        #send_msg(addr)
        print (addr, access)

get_target_addr()

