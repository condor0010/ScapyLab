#!/bin/python
from scapy.all import *
from operator import xor
import sys

def gb(pkt):
    ret = (chr(int(pkt[ARP].pdst.split(".")[3])))
    if (ret == chr(3)):
        sys.exit(0)
    else:
        print(chr(xor(ord(ret), 2)))


while True:
    sniff(filter="arp", count=1, prn=gb)

