#!/usr/bin/env python

from scapy.all import *
from scapy.packet import *
# from scapy.supersocket import StreamSocket


class IFAHeader(Packet):
    name = "Broadcom IFA2 Header"
    fields_desc = [
        BitField("version", 0, 4),
        BitField("gns", 0, 4),
        BitField("proto", 0, 8),
        FlagsField("flags", 0, 8, {
            3: "MF",
            4: "TS",
            5: "I",
            6: "TA",
            7: "C"
        }),
        BitField("maxLength", 0, 8)
    ]

class IFAMeta(Packet):
    name = "IFA Metadata Fields"
    fields_desc = [
        # first octet
        BitField("lns", 0, 4),
        BitField("deviceID", 0, 20),
        BitField("ipTTL", 0, 8),
        # second octet
        BitField("congestion", 0, 4),
        BitField("queueID", 0, 8),
        BitField("rxTimestampSec", 0, 20),
        # third octet
        BitField("egressPort", 0, 16),
        BitField("ingressPort", 0, 16),
        # extra timestamp & data
        BitField("rxTimestampNanoSec", 0, 32),
        BitField("residenceTimeNanoSec", 0, 32),
        BitField("opaqueData1", 0, 32),
        BitField("opaqueData2", 0, 32),
    ]

class IFAMetaHeader(Packet):
    name = "IFA Metadata Header"
    fields_desc = [
        BitField("requestVec", 0, 8),
        BitField("actionVec", 0, 8),
        BitField("hopLimit", 0xff, 8),
        BitField("curLength", 0, 8),
        PacketListField("metadata", [], IFAMeta, length_from=lambda p:p.curLength*7)
    ]

class IFAChecksum(Packet):
    name = "IFA Checksum Header"
    fields_desc = [
        BitField("chksum", 0, 16),
        BitField("rsvd", 0, 16)
    ]

class IFAMetaFrag(Packet):
    name = "IFA Metadata Fragmentation Header"
    fields_desc = [
        BitField("pktid", 0, 26),
        BitField("mfid", 0, 6),
        BitField("I", 0, 1)
    ]


if __name__ == "__main__":
    def get_basic_IFAv2():
        ip_hdr = IP(proto=253)
        tcp_hdr = TCP(sport=80, dport=80)
        ifa_hdr = IFAHeader(version=2, gns=0xf, proto=0x11, flags=[], maxLength=0xff)
        ifa_meta_hdr = IFAMetaHeader(requestVec=1, actionVec=2, curLength=5)
        pkt = ip_hdr / ifa_hdr / tcp_hdr / ifa_meta_hdr / b"magic_code(0xdeafbeaf)\n"
        return pkt

    pkt = get_basic_IFAv2()
    pkt.show()
    send(pkt)