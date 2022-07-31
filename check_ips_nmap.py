import pprint
import sys,os
import json
import socket
from nmap import nmap
from multiprocessing import Pool
#import nmap

'''
    python version 3.8 or above
    pip install python-nmap
'''

detail = dict()

#fi is reference for port scanner
def describe_service_open(fi,ip):
    hnames = fi.all_hosts()
    detail.update({ip:{'hnames':hnames}})
    network_interface = dict()
    for host in fi.all_hosts():
        # print('Host : %s (%s)' % (host, fi[host].hostname()))
        # print('State : %s' % fi[host].state())
        for proto in fi[host].all_protocols():
            print('Protocol : %s' % proto)
            lport = list(fi[host][proto].keys())
            lport.sort()
            for port in lport:
                # print ('port : %s\tstate : %s' % (port, fi[host][proto][port]['state']))
                state = fi[host][proto][port]['state']
                service = fi[host][proto][port]['name']
                network_interface.update({port:{'service':service,'state':state}})
    detail[ip]['n_int'] = network_interface
    return detail


def main():
    response = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan
                4)Regular Scan
                5. OS Detection
                6. Multiple IP inputs
                7. Ping Scan\n""")
    print("You have selected option: ", response)

    from optparse import OptionParser
    parser = OptionParser(usage='python %prog --ips --cred', prog=sys.argv[0],)
    parser.add_option("--ips",type="string",dest="ips")
    # parser.add_option("--cred",type="string", dest="cred")
    (options, args) = parser.parse_args()
    # if not getattr(options,'ips') and not getattr(options,'cred'):
    if not getattr(options,'ips') :
        # print(" please provide input --ips coma seprated ip address and --cred coma seprated credentials coma seprated")
        print(" please provide input --ips coma seprated ip address")
        sys.exit(0)
    ips = options.ips.split(',')
    # cred = options.cred.split(',')
    # def merge(ips,cred):L
    #     tups = [(ips[i],cred[i]) for i in range(0,len(ips))]
    #     return tups
    # ips_cred = merge(ips,cred)
    for ip in ips:
        ip = '127.0.0.1' if ip == 'localhost' else ip
        fi = nmap.PortScanner()
        print("Nmap Version: ", fi.nmap_version())
        if response in ['1','2','3','5','6','7'] and  not os.geteuid() == 0:
            print("\n ***** Only Root can run this operation *******\n")
            sys.exit(0)
        if response == '1':
            try:
                fi.scan(ip,'1-1024', '-v -sS')
                print("Ip Status: ", fi[ip].state())
                print("protocols:",fi[ip].all_protocols())
                print("Open Ports: ", fi[ip]['tcp'].keys())
            except Exception as e:
                pprint.pprint(e)
        elif response == '2':
            try:
                fi.scan(ip,'1-1024', '-v -sU')
                print("Ip Status: ", fi[ip].state())
                print("protocols:",fi[ip].all_protocols())
                print("Open Ports: ", fi[ip]['udp'].keys())
            except Exception as e:
                pprint.pprint(e)
        elif response == '3':
            try:
                # sS for SYN scan, sv probe open ports to determine what service and version they are running on
                fi.scan(ip,'1-1024', '-v -sS -sV -sC -A -O')
                print("Ip Status: ", fi[ip].state())
                print("protocols:",fi[ip].all_protocols())
                print("Open Ports: ", fi[ip]['tcp'].keys())
                service_detail = describe_service_open(fi,ip)
                return json.dumps(service_detail)
            except Exception as e:
                pprint.pprint(e)
        elif response == '4':
            try:        
                fi.scan(ip)
                print("Ip Status: ", fi[ip].state())
                print("protocols:",fi[ip].all_protocols())
                print("Open Ports: ", fi[ip]['tcp'].keys())
                # service_detail = describe_service_open(fi,ip)
                # return json.dumps(service_detail)
            except Exception as e:
                pprint.pprint(e)
        elif response == '5':
            fi.scan(ip, arguments="-O")
            print(fi.__dict__)
        elif response == '6':
            print("Nmap Version: ", fi.nmap_version())
            fi.scan(ip,'1-1024', '-v -sS')
            print(fi.scaninfo())
            # state() tells if target is up or down
            print("Ip Status: ", fi[ip].state())
            # all_protocols() tells which protocols are enabled like TCP UDP etc
            print("protocols:",fi[ip].all_protocols())
            print("Open Ports: ", fi[ip]['tcp'].keys())
        elif response == '7': 
            ip = ip + '/24'
            fi.scan(hosts=ip, arguments='-n -sP -PE -PA21,23,80,3389')
            hosts_list = [(x, fi[x]['status']['state']) for x in fi.all_hosts()]
            for host, status in hosts_list:
                print('{0}:{1}'.format(host, status))
        else:
            pprint.pprint(" Please select a valid option ")
            sys.exit(0)

if __name__ == '__main__':
    pprint.pprint(main())
