#!/usr/bin/env python

import socket
import os
import multiprocessing
from scapy.all import *
from scapy.packet import *
from scapy.supersocket import StreamSocket

from ifav2 import *

LOCAL_IF = ""
PEER_IP = "127.0.0.1"
DPORT = 0x9091
PEER_PORT = 7000
CONST_PAYLOAD = b"\xff" * 8 * 8 + b"magic_code(0xdeadbeaf-%d-%d)\n"
PKT_COUNTER = 0
PROCESS_ID = 0

# def get_connected_socket():
#     s = socket.socket()
#     s.connect((PEER_IP, PEER_PORT))
#     # ss = StreamSocket(s, Raw)
#     # ss.sr1(Raw("GET /\r\n"))
#     return s

def get_env():
    import sys
    global PROCESS_ID
    PROCESS_ID = multiprocessing.current_process().pid
    if len(sys.argv) == 4:
        global LOCAL_IF
        LOCAL_IF = sys.argv[1]

        try:
            socket.inet_aton(sys.argv[2])
            global PEER_IP
            PEER_IP = sys.argv[2]
        except socket.error:
            print("Error IP Address")
            exit(1)
    else:
        print("Usage: %s Interface DesIP Parallel" % sys.argv[0])
        exit(1)

def get_payload():
    global PKT_COUNTER
    global DPORT
    DPORT += 1
    PKT_COUNTER += 1
    s = CONST_PAYLOAD % (PROCESS_ID, PKT_COUNTER)
    return s

def get_basic_IFAv2():
    eth_hdr = Ether()
    ip_hdr = IP(dst=PEER_IP, proto=253)
    l4_hdr = UDP(sport=0x8081, dport=DPORT)
    ifa_hdr = IFAHeader(version=2, gns=0xf, proto=0x11, flags=[], maxLength=0x80)
    ifa_meta_hdr = IFAMetaHeader(requestVec=0, actionVec=0, hopLimit=0x1f, curLength=0)
    raw_data = get_payload()
    pkt = eth_hdr / ip_hdr / ifa_hdr / l4_hdr / ifa_meta_hdr / raw_data
    return pkt

def get_socket():
    global LOCAL_IF
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((LOCAL_IF, 0))
    return s

def flood():
    get_env()
    print("PROCESS %d running..." % (PROCESS_ID))

    sk = get_socket()
    pkts = PacketList()
    pkts_raw = []
    for i in range(1*1000):
        pkt = get_basic_IFAv2()
        pkts.append(pkt)
        pkts_raw.append(pkt.build())
        # sk.send(pkt.build())

    print("PROCESS %d flooding..." % (PROCESS_ID))
    round = 0
    while True:
        for p in pkts_raw:
            sk.send(p)
        round += 1
        if round % 100 == 0:
            print("%d: %d Kpkts" % (PROCESS_ID, round))
        # if round == 50 * 100:
        #     break

    print("Process %d exiting..." % PROCESS_ID)

def test():
    pid = multiprocessing.current_process().pid
    ospid = os.getpid()
    print("test", pid, ospid)

def process_exit(argv):
    print("Process %d exiting with %s ..." % (PROCESS_ID, str(argv)))

if __name__ == "__main__":
    if len(sys.argv) == 4:
        parallel = int(sys.argv[3])
    else:
        print("Usage: %s Interface DesIP Parallel" % sys.argv[0])
        exit(1)

    print("Setup process pool: %d" % parallel)
    time.sleep(1)

    pool = multiprocessing.Pool(processes=parallel)

    for i in range(parallel):
        pool.apply_async(flood, error_callback=process_exit)

    pool.close()
    pool.join()

