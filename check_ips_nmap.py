#!/home/punit/main-env/bin/python
import pprint
import sys
import json
import socket
from nmap import nmap

def main():
    pass

if __name__ == '__main__':
     from optparse import OptionParser
     parser = OptionParser(usage='python %prog --ips --cred', prog=sys.argv[0],)
     parser.add_option("--ips",type="string",dest="ips")
     parser.add_option("--cred",type="string", dest="cred")
     (options, args) = parser.parse_args()
     if not getattr(options,'ips') and not getattr(options,'cred'):
         print(" please provide input --ips coma seprated ip address and --cred coma seprated credentials coma seprated")
         sys.exit(0)
     ips = options.ips.split(',')
     cred = options.cred.split(',')
     def merge(ips,cred):
         tups = [(ips[i],cred[i]) for i in range(0,len(ips))]
         return tups
     ips_cred = merge(ips,cred)
     detail = dict()
     try:
         pass
     except Exception as e:
          print(e)
     for ip in ips:
         fi = nmap.PortScanner()
         fi.scan(ip)
         #print(fi)
         hnames = fi.all_hosts()
         detail.update({ip:{'hnames':hnames}})
         network_interface = dict()
         for host in fi.all_hosts():
             print('Host : %s (%s)' % (host, fi[host].hostname()))
             print('State : %s' % fi[host].state())
             for proto in fi[host].all_protocols():
                 print('Protocol : %s' % proto)
                 lport = list(fi[host][proto].keys())
                 lport.sort()
                 for port in lport:
                     print ('port : %s\tstate : %s' % (port, fi[host][proto][port]['state']))
                     state = fi[host][proto][port]['state']
                     service = fi[host][proto][port]['name']
                     network_interface.update({port:{'service':service,'state':state}})
         type(detail[ip])
         detail[ip]['n_int'] = network_interface
         print(fi.csv())
     print(detail)
