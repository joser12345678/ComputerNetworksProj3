#!/usr/bin/env python3
import argparse
from multiprocessing import Semaphore
from scapy.all import DNS
import re
import socket
import ipaddress
from threading import *

# globals
enable_DoH = False
deny_list_file = "NOT SPECIFIED"
log_file = "NOT SPECIFIED"
dns_server = "8.8.8.8"
query_list = list()

# producer consumer synchronization
sem_empty = Semaphore(10)
sem_full = Semaphore(0)
mutex = Lock()

# main socket mutex for syncronization
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# query class that holds information for each query.
class Query:
    def __init__(self, address, message):
        self.client_addr = address      #store client info
        self.client_message = message   # store the client message
        self.response = ""      # store string of the response
        print("Query Created. CLient Info: " + str(self.client_addr))

    # parses and checks udp packet, returns the reply contents if successful
    def udp_style(self):
        # use message to create the dns object
        packet = DNS(self.client_message)
        dns_id = packet.id

        # only send requests
        dns_opcode = packet.opcode
        if dns_opcode != 0:
            return 0
        
        #for now, lets just send the packet
        query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        query_sock.sendto(self.client_message, (dns_server, 53))

        # revieve the repoy and send it to the client
        query_sock.settimeout(1)
        msgFromServer, addr = query_sock.recvfrom(4096)
        packet = DNS(msgFromServer)
        if dns_id != packet.id:
            return 0

        return msgFromServer



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
    global query_list

    while True:
        data, addr = sock.recvfrom(4096)

        sem_empty.acquire()
        mutex.acquire()

        query_list.append(Query(addr, data))

        mutex.release()
        sem_full.release()
        


# consumer function that will perform all queries on behalf of the client
def consumer():
    while True:
        # get a query to fill
        sem_full.acquire()
        mutex.acquire()
        curr_query = query_list.pop(0)
        mutex.release()
        sem_empty.release()

        # now, we will fulfill this query
        if enable_DoH:
            print("DOH NOT IMPLEMENTED")
        else:
            query_reply = curr_query.udp_style()
            if query_reply == 0:
                continue
            sock.sendto(query_reply, curr_query.client_addr)
        

if __name__ == '__main__':
    setParams()

    # bind socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 53))

    x = Thread(target=consumer)
    x.start()

    listener()