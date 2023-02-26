import argparse
import json
import logging
import socket
from multiprocessing import Pool

import nmap

logging.basicConfig(level=logging.INFO, format='%(message)s')

def scan_ports(ip, scan_type):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments=scan_type)
        if scanner[ip].state() == 'up':
            protocols = scanner[ip].all_protocols()
            for protocol in protocols:
                ports = scanner[ip][protocol].keys()
                for port in ports:
                    state = scanner[ip][protocol][port]['state']
                    service = scanner[ip][protocol][port]['name']
                    logging.info(f"IP: {ip} | Port: {port} | Protocol: {protocol.upper()} | State: {state} | Service: {service}")
        else:
            logging.info(f"IP: {ip} | State: {scanner[ip].state()}")
    except Exception as e:
        logging.error(f"Error scanning ports for IP {ip}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Port scanner using Nmap.")
    parser.add_argument("--ips", type=str, help="Comma-separated list of IP addresses to scan.")
    parser.add_argument("--scan-type", type=str, choices=["SYN-ACK", "UDP", "Comprehensive", "Regular", "OS-detection", "Ping"], help="Type of scan to perform.")
    args = parser.parse_args()

    if not args.ips:
        logging.error("Please provide a comma-separated list of IP addresses to scan.")
        return

    ips = args.ips.split(",")
    scan_type = ""
    if args.scan_type:
        if args.scan_type == "SYN-ACK":
            scan_type = "-v -sS"
        elif args.scan_type == "UDP":
            scan_type = "-v -sU"
        elif args.scan_type == "Comprehensive":
            scan_type = "-v -sS -sV -sC -A -O"
        elif args.scan_type == "Regular":
            scan_type = ""
        elif args.scan_type == "OS-detection":
            scan_type = "-O"
        elif args.scan_type == "Ping":
            scan_type = "-sn"

    with Pool() as p:
        p.starmap(scan_ports, [(ip.strip(), scan_type) for ip in ips])

if __name__ == "__main__":
    main()
