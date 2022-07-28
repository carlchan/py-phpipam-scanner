#!/usr/bin/env python

from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from threading import Lock
import phpypam
import ipaddress
import dns.resolver
import sys
import socket
import platform    # For getting the operating system name
import subprocess  # For executing a shell command
import yaml

try:
    with open('scanagent-conf.yaml') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
except:
    print('failed loading config file')
    sys.exit(1)

pi = phpypam.api(
    url=config['ipam_url'],
    app_id=config['app_id'],
    username=config['username'],
    password=config['password'],
    ssl_verify=config['ssl_verify']
)

if config['ssl_verify'] == False:
    from urllib3.exceptions import InsecureRequestWarning
    from urllib3 import disable_warnings
    disable_warnings(InsecureRequestWarning)

try:
    maxthreads=config['maxthreads']
except:
    try:
        maxthreads=multiprocessing.cpu_count()
    except:
        maxthreads=2
        pass

def ping(host):
    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', '-t', '1', host]

    return subprocess.call(command,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT) == 0

def checksock(host,port):
    # print('checking',host,'port',port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        s.close()
        # print('port',port,'open on',host)
        return True
    except:
        return False

def rlookup(ip):
    try:
        return dns.resolver.resolve(dns.reversename.from_address(ip), 'PTR')[0].to_text()
    except:
        return ip

def update_host(host):
    try:
        subnetid=pi.get_entity(controller='subnets', controller_path = "overlapping/"+str(host)+'/32')[0]["id"]
    except Exception as e:
        print('failed getting subnetid:',e)
        return False

    try:
        hostid=pi.get_entity(controller='addresses', controller_path = "search/"+str(host))[0]["id"]
    except:
        hostid=None
        pass

    try:
        hostname=rlookup(host)
    except:
        hostname=''

    if hostid:
        #update host
        hostdata = {
            'id': hostid,
            'hostname': hostname,
            'tag':2,
        }
        try:
            result=pi.update_entity(controller='addresses', controller_path = hostid, data=hostdata)
            return result
        except Exception as e:
            print('failed updating host ',hostdata, ':', e)
            return False
    else:
        #create new host
        hostdata = {
            'hostname': hostname,
            'ip': host,
            'subnetId': subnetid,
            'tag':2,
        }
        try:
            result=pi.create_entity(controller='addresses', data=hostdata)
            return result
        except Exception as e:
            print('failed creating host',host,':',e)
            return False

def scan(host):
    is_online=False
    if ping(host):
        # print('ping ok',host)
        is_online=True
    else:
        # print('portscanning',host)
        ports=config['scanports']
        try:
            results=[]
            with ThreadPoolExecutor(max_workers=maxthreads) as executor:
                for port in ports:
                    result=executor.submit(checksock, host, port)
                    results.append(result)
            for result in results:
                if result.result():
                    is_online=True
                    break
        except Exception as e:
            print('failed portscanning',host,':',e)
            return

    if is_online:
        # print('host is online',host)
        try:
            return update_host(host)
        except Exception as e:
            print('failed updating host',host,':',e)
            return False
    else:
        # print('host is offline',host)
        return False

def progress(future):
    global lock,tasks_total,tasks_completed
    with lock:
        tasks_completed+=1
        print('\r',tasks_completed,'/',tasks_total,end=' IPs scanned')

if __name__ == '__main__':
    try:
        scanlist = sys.argv[1:]
    except Exception as e:
        print('failed getting scanlist:',e)
        sys.exit(1)

    lock=Lock()
    tasks_total=0
    tasks_completed=0
    with ThreadPoolExecutor(max_workers=maxthreads) as pool:
        # print('Starting scanagent with',maxthreads,'threads')
        count = 0
        tasks=[]
        print('Scan targets:'," ".join(scanlist))
        for net in scanlist:
            if ':' in net:
                iplist=[str(ip) for ip in ipaddress.IPv6Network(net)]
            else:
                iplist=[str(ip) for ip in ipaddress.IPv4Network(net)]
            tasks_total+=len(iplist)
            tasks += [pool.submit(scan, host) for host in iplist]
        for task in tasks:
            task.add_done_callback(progress)
    print('\nScan complete')

