#!/usr/bin/env python

from concurrent.futures import ThreadPoolExecutor
import phpypam
import ipaddress
import dns.resolver
import sys
import socket
import platform    # For getting the operating system name
import subprocess  # For executing a shell command

import yaml

configfile='scanagent-conf.yaml'
try:
    with open(configfile) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
except:
    print('Could not load config file',configfile)
    sys.exit(1)

pi = phpypam.api(
    url=config['ipam_url'],
    app_id=config['app_id'],
    username=config['username'],
    password=config['password'],
    ssl_verify=config['ssl_verify']
)
maxthreads=config['maxthreads']

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

    if hostid:
        #update host
        hostdata = {
            'id': hostid,
            'hostname': rlookup(host),
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
            'hostname': rlookup(host),
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

if __name__ == '__main__':
    try:
        scanlist = sys.argv[1:]
    except Exception as e:
        print('failed getting scanlist:',e)
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=maxthreads) as pool:
        count = 0
        for net in scanlist:
            iplist=[str(ip) for ip in ipaddress.IPv4Network(net)]
            print('Scanning network:',net)
            for ip in iplist:
                pool.submit(scan, ip)
                count += 1
    print('updated',count,'hosts')
