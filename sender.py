#!/bin/python
from scapy.all import *

# set interface to wlp4s0
conf.iface="wlp4s0"

# stop scapy from printing junk
conf.verb = 0

# set source and destination adresses
mac_src = "00:00:00:00:00:00"
mac_dst = "ff:ff:ff:ff:ff:ff"

# make ethernet headder
ether = Ether(src=mac_src, dst=mac_dst)

def mk_pkt(lttr):
    ip_addr = "0.0.0."+str(ord(lttr))
    arp = ARP(pdst=ip_addr) # make arp request
    packet = ether/arp # make packet
    sendp(packet) # send packet


msg = "horney goat weed"

for lttr in msg:
    mk_pkt(lttr)
