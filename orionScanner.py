import argparse
import os, sys
import ipaddress
import nmap3
import favicon
import requests
requests.packages.urllib3.contrib.pyopenssl.extract_from_urllib3()
import codecs, mmh3

# adding argparse modules
parser = argparse.ArgumentParser()
parser.add_argument("-t","--target", help="Single IP",type=str)
parser.add_argument("-T","--targets", help="List of IP in text file",type=str)
parser.add_argument("-c","--cidr", help="CIDR range",type=str)
parser.add_argument('-a',"--add", help="Addition ports to check for. example: -a 8889,9991",type=str)
args = parser.parse_args()
if len(sys.argv) < 2:
    parser.print_help()
    sys.exit(1)

def orionNmap(ip):
    nmap = nmap3.NmapHostDiscovery()
    if args.add:
        print("Checking default web ports and additional ports {1} for {0}!".format(ip,args.add)) 
        result=nmap.nmap_portscan_only("{0} -p 443,80,8443,8080,{1} -n -sS".format(ip,args.add))
    else:
        print("Checking default web ports for {0}!".format(ip))    
        result=nmap.nmap_portscan_only("{0} -p 443,80,8443,8080 -n -sS".format(ip))
    ip_r=list(result.keys())
    port=list()
    if ip_r[0] == 'runtime':
        print("No default web port is open")
    else:
        for i in range(len(result[ip_r[0]])):
            if result[ip_r[0]][i]['state'] == 'open':
                portid=int(result[ip_r[0]][i]['portid'])
                port.append(portid)
                print("->{0}: UP".format(portid))
    return port

def icon_hash(ip,port):
    if port in [443,8443]:
        url="https://{0}:{1}/".format(ip,port)
    else:
        url="http://{0}:{1}/".format(ip,port)
    icons = favicon.get(url,verify=False)
    response = requests.get(icons[0][0],verify=False)
    iconHash = codecs.encode(response.content,"base64")
    hash = mmh3.hash(iconHash)
    if hash==-1776962843:
        print("Solarwinds Orion is present in {0}:{1}\n".format(ip,port))
        info[ip]=port
if __name__=="__main__":
    info=dict()

    if args.target:
        ip_list=[args.target]
        
    if args.targets:
        ip_list=fileload(args.targets)
               
    if args.cidr:
        ip_list=[str(ip) for ip in ipaddress.IPv4Network(args.cidr)]

    if len(ip_list)==0:
        print("Required argument:\n-t or -T or -c         Single Ip/file with ip list/cidr")
        sys.exit(1)
        
    for ip in ip_list:
        port=orionNmap(ip)
        if len(port) !=0:
            for i in port:
                icon_hash(ip,i)
            
    if len(info)!=0:
        print("Overall Detected solarwinds orion")
        print("{:>25}{:>25}".format("IP","port"))
        print("{:>25}{:>25}".format("--------------","----------"))
        for i in info:
            print("{:>25}{:>25}".format(i,info[i]))
    else:
        print("No web application was detected")
