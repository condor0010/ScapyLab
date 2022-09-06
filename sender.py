#!/bin/python
from scapy.all import *
from time import sleep
from operator import xor
import random
conf.iface="virbr0" # set interface to wlp4s0
conf.verb = 0 # stop scapy from printing junk

mac_src = "00:00:00:00:00:00" # set source mac adress
mac_dst = "ff:ff:ff:ff:ff:ff" # set destination mac adress

# make ethernet headder
ether = Ether(src=mac_src, dst=mac_dst)

def mk_pkt(lttr):
    ip_addr = "192.168.1."+str(xor(ord(lttr), 2))
    arp = ARP(pdst=ip_addr) # make arp request
    packet = ether/arp # make packet
    sendp(packet) # send packet


msg = "scapy is awsome"

for lttr in msg:
    mk_pkt(lttr)
    slp = (2+random.random())
    print(slp)
    sleep (slp)
mk_pkt(chr(1))
