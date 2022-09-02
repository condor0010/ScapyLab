#!/bin/python
from scapy.all import *

def gb(pkt):
    print(chr(int(pkt[ARP].pdst.split(".")[3])))


while True:
    pkt = sniff(filter="arp", count=1, prn=gb)

