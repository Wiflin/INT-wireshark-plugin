#!/usr/bin/env python

import socket
import scapy
from scapy.all import *

LOCAL_IP = "0.0.0.0"
LOCAL_PORT = 7000

def get_listen_socket():
    s = socket.socket()
    s.bind((LOCAL_IP, LOCAL_PORT))
    s.listen()
    print("listening..")
    return s

def handle_connection(s):
    while True:
        con, addr = s.accept()
        print(addr)
        with con:
            msg = con.recv(1024)
            con.send(msg)
            print(msg)

def get_pkts_from_pcap(file):
    pkts = rdpcap(file)
    return pkts

def dissert_ifa(pkt):
    pass

if __name__ == "__main__":
    # s = get_listen_socket()
    # handle_connection(s)
    pkts = get_pkts_from_pcap('ifa.cap')
    p = pkts[0]
    p.summary()
    p.show()
    dissert_ifa()