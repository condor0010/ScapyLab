#!/bin/python
from scapy.all import *
import sys

def gb(pkt):
    ret = (chr(int(pkt[ARP].pdst.split(".")[3])))
    if (ret == chr(1)):
        sys.exit(0)
    else:
        print(ret)


while True:
    sniff(filter="arp", count=1, prn=gb)

