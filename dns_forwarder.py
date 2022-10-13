#!/usr/bin/env python3
import argparse
import scapy
import re
import socket
import ipaddress

# globals
enable_DoH = False
deny_list_file = "NOT SPECIFIED"
log_file = "NOT SPECIFIED"
dns_server = "8.8.8.8"

# query class that holds information for each query.
class Query:
    def __init__(self):
        print("NOT IMPLEMENTED")

# sets up parser and parses options
# makes sure the prefix is specified
def setParams():
    parser = argparse.ArgumentParser(description="dns forwarder with support for DoH")
    parser.add_argument('-d', metavar='DST_IP', type=str,
                        help="Destination DNS server IP")
    parser.add_argument('-f', metavar='DENY_LIST_FILE', type=str,
                        help="File containing domains to block")
    parser.add_argument('-l', metavar='LOG_FILE', type=str,
                        help="Append-only log file")
    parser.add_argument('--doh', action='store_true',
                        help="Use default upstream DoH server")
    parser.add_argument('--doh_server', metavar='DOH_SERVER', type=str,
                        help="Use this upstream DoH server")

    # parse arguments and put into args
    args = parser.parse_args()

    global enable_DoH, deny_list_file, log_file, dns_server
    # if doh_server is specified, set ip and enable doh
    if args.doh_server:
        enable_DoH = True
        dns_server = args.doh_server
    elif args.doh:
        enable_DoH = True

    elif (not args.doh_server) and (not args.doh):
        if not args.d:
            print("Error: must contain DST_IP")
            exit()  
        dns_server = args.d
        # check ip to make sure it is valid
        try:
            ipaddress.ip_address(dns_server) 
        except ValueError:
            print("Invalid DNS server IP")
            exit()
    
    if args.l:
        log_file = args.l
    if args.f:
        deny_list_file = args.f

    print("DoH enabled: " + str(enable_DoH))
    print("Deny list file: " + deny_list_file)
    print("Log file: " + log_file)
    print("Server IP: " + dns_server)


# listener that listens for traffic
def listener():
    # bind socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    
    while True:
        data, addr = sock.recvfrom(4096)
        print(data)
        print("======================================")
        print(addr)


# consumer function that will perform all queries on behalf of the client
def consumer():
    print("NOT IMPLEMENTED")

if __name__ == '__main__':
    setParams()
    listener()