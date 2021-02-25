import subprocess
import sys
import signal
import re
import json
import os
import threading
import queue
import datetime
import argparse

global fd
global FAIL_DETECT, PASS_DETECT, GROUP_GET
global DATE_FMT
global DB_LIST
global THREAD_FD
global DB_FILENAME
global UNBAN_LIMIT
global MAX_ATTEMPTS
global FILENAME
global comm

#Regex matching
FAIL_DETECT = '(message repeated.*)?Failed password.*ssh'
PASS_DETECT = '(message repeated.*)?Accepted password.*ssh' 
IP_ADDRESS_GET = '(?<=from )[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
MSG_REPEAT_GET = '(?<=message repeated )[0-9]+(?= times)'

#Date format for datetime.strptime
DATE_FMT = '%Y-%m-%d %H:%M:%S.%f'

DB_FILENAME = 'database'
DB_LIST = {}
THREAD_FD = None

def signal_handler(sig, frame):
    global comm
    fd.kill()

    if THREAD_FD != None:
        report = {}
        report['OPERATION'] = "Q"
        report["IP_ADDR"] = ''
        report["COUNT"] = 0
        comm.put(report)
        THREAD_FD.join()

    #write_db(DB_FILENAME, DB_LIST)
    
    print("\nApplication stopped..")
    sys.exit(0)

def ban_ip(ip_address):
    command = ['iptables',
                '-A', 'INPUT',
                '-s', ip_address+'/32',
                '-m', 'tcp', '-p', 'tcp',
                '--dport', '22',
                '-j', 'DROP']


    f = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    output = f.stderr.readline()
    f.terminate()
    if output != b'':
        print("Error: ", output)
        return 1
    print("Banned ip address: {}".format(ip_address))
    return 0

def unban_ip(ip_address):
    command = ['iptables',
                '-D', 'INPUT',
                '-s', ip_address+'/32',
                '-m', 'tcp', '-p', 'tcp',
                '--dport', '22',
                '-j', 'DROP']
    while True:
        f = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = f.stderr.readline()
        f.terminate()
        
        if (output == b''):
            continue
        elif (re.search('Bad rule', output.decode()) != None):
            #Normal operation
            break
        else:
            #Not normal operation
            print("Error: ", output)
            break
    print("Unbanned ip address: {}".format(ip_address))



def read_db(filename):
    if not(os.path.exists(filename)):
        print("Warning database file not found!")
        return {}
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except:
        print("Unable to read database file, rewriting new file")
        return {}

def write_db(filename, data):
    try:
        with open(filename, 'w+') as f:
            json.dump(data, f)
    except:
        print("Unable to write to database, ensure proper access is given")
        return 1
    return 0

def thread_process(comm):
    global DB_LIST
    global DATE_FMT
    global UNBAN_LIMIT
    global MAX_ATTEMPTS

    unban_time = UNBAN_LIMIT
    max_attempts = MAX_ATTEMPTS
    ban_time = None
    item = None
    changed = False

    while True:
        
        ip_addresses = [i for i in DB_LIST.keys()]
        for ip_addr in ip_addresses:
            if DB_LIST[ip_addr][2] == "B":
                # Check time for unban
                ban_time = datetime.datetime.strptime(DB_LIST[ip_addr][1], DATE_FMT)
                if (unban_time >= 0) and ((datetime.datetime.now() - ban_time) > datetime.timedelta(minutes = unban_time)):
                    # Unban
                    unban_ip(ip_addr)
                    DB_LIST.pop(ip_addr,None)
                    changed = True
            elif DB_LIST[ip_addr][2] == "U":
                # Check if ban is needed
                if (max_attempts >=0) and DB_LIST[ip_addr][0] >= max_attempts:
                    #Ban
                    ban_ip(ip_addr)
                    DB_LIST[ip_addr][2] = "B"
                    DB_LIST[ip_addr][1] = str(datetime.datetime.now())
                    changed = True
        if changed == True:
            write_db(DB_FILENAME, DB_LIST)
        try:
            item = comm.get(timeout=1)
            changed = False
        except queue.Empty:
            continue

        if item["OPERATION"] == "Q":
            break
        elif item["OPERATION"] == "F":
            if item["IP_ADDR"] in DB_LIST:
                DB_LIST[item["IP_ADDR"]][0] += item["COUNT"]
                changed = True
            else:
                DB_LIST[item["IP_ADDR"]] = []
                DB_LIST[item["IP_ADDR"]].append(item["COUNT"])
                DB_LIST[item["IP_ADDR"]].append('')
                DB_LIST[item["IP_ADDR"]].append("U")
                changed = True
        elif item["OPERATION"] == "S":
            DB_LIST.pop(item["IP_ADDR"], None)
            changed = True
        else:
            print("WARNING: Unknown message {}".format(item))

def check_iptables_rights():
    print("Checking administrative rights...")
    f = subprocess.Popen(['iptables', '-L'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = f.stderr.readline()
    f.terminate()
    if output != b'':
        if (re.search('Permission denied', output.decode()) != None):
            return [1,output]
        else:
            return [2,output]
    return [0,'']


def main():
    global fd
    global FAIL_DETECT, PASS_DETECT, IP_ADDRESS_GET, MSG_REPEAT_GET
    global DATE_FMT
    global DB_LIST
    global THREAD_FD
    global DB_FILENAME
    global FILENAME
    global MAX_ATTEMPTS
    global UNBAN_LIMIT
    global comm

    comm = queue.Queue()
    ban_inc = 1
    msg = ''
    parameters = None
    ip_addr = None

    parser = argparse.ArgumentParser(description='SSH monitoring program. Bans IP addresses based on the number of attempts and unbans after some time.')

    parser.add_argument('-f', '--file' , help='the SSH auth.log file. Defaults to /var/log/auth.log', default='/var/log/auth.log', type=str)
    parser.add_argument('-d', '--database' , help='the JSON database filename. Defaults to ./database', default='./database', type=str)
    parser.add_argument('-m', '--max_attempts' , help='maximum number of SSH login attempts before the ban. -1 for no ban. Default is 3', default=3, type=int)
    parser.add_argument('-u', '--unban_limit' , help='Unbanning time in minutes. -1 for indefinite. Default is -1', default=-1, type=int)

    args = parser.parse_args()
    FILENAME = args.file
    DB_FILENAME = args.database
    MAX_ATTEMPTS = args.max_attempts
    UNBAN_LIMIT = args.unban_limit


    print(''' ______   _______  _               _______  _______          
(  ___ \ (  ___  )( (    /|       (  ____ \(  ____ \|\     /|
| (   ) )| (   ) ||  \  ( |       | (    \/| (    \/| )   ( |
| (__/ / | (___) ||   \ | | _____ | (_____ | (_____ | (___) |
|  __ (  |  ___  || (\ \) |(_____)(_____  )(_____  )|  ___  |
| (  \ \ | (   ) || | \   |             ) |      ) || (   ) |
| )___) )| )   ( || )  \  |       /\____) |/\____) || )   ( |
|/ \___/ |/     \||/    )_)       \_______)\_______)|/     \|
                                                             ''')
    print("Target log file set to: {}".format(FILENAME))
    print("Target database file set to: {}".format(DB_FILENAME))
    print("Max attempts set to: {}".format(str(MAX_ATTEMPTS) + " attempt(s)" if MAX_ATTEMPTS >= 0 else 'No ban'))
    print("Unban limit set to: {}".format(str(UNBAN_LIMIT) + " minute(s)"  if UNBAN_LIMIT >= 0 else 'INDEFINITE'))
    print("")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    filename = FILENAME
    db_filename = DB_FILENAME
    
    error, output = check_iptables_rights()
    if error == 1:
        print("Error, need administrative rights.")
        return 0
    elif error == 2:
        print("Error, unknown: ", output)
        return 0
    else:
        print("OK")
    print("")

    DB_LIST = read_db(db_filename)

    THREAD_FD = threading.Thread(target=thread_process, args=(comm,))
    THREAD_FD.start()

    print("Starting watcher thread...")
    fd = subprocess.Popen(['tail','-f', '-c 0', filename], stdout=subprocess.PIPE)

    print("Application Running...")
    print("Ctrl-C to stop application")
    while True:
        report = {}
        ban_inc = 1

        line = fd.stdout.readline().decode()
        
        msg = re.search(FAIL_DETECT, line)
        if (msg != None):
            msg = msg.group(0)
            #print("Failed!")
            parameters = re.search(MSG_REPEAT_GET, msg)
            ban_inc = 1 if parameters == None else int(parameters.group(0))
            
            parameters = re.search(IP_ADDRESS_GET, msg)
            ip_addr = parameters.group(0) if parameters != None else None
            
            report["OPERATION"] = "F"
            report["IP_ADDR"] = ip_addr
            report["COUNT"] = ban_inc

            comm.put(report)
            #print("Ban increment: {}, IP address: {}".format(ban_inc, ip_addr))
            continue
        
        msg = re.search(PASS_DETECT, line)
        if (msg != None):
            msg = msg.group(0)
            #print("Success!")
            parameters = re.search(IP_ADDRESS_GET, msg)
            ip_addr = parameters.group(0) if parameters != None else None
            
            report["OPERATION"] = "S"
            report["IP_ADDR"] = ip_addr
            report["COUNT"] = 0

            comm.put(report)
            #print("IP address: {}".format(ip_addr))
            continue
        
        # Not SSH related
        continue
        


if __name__ == '__main__':
    main()
