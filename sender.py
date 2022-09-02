#!/bin/python
from scapy.all import *
from time import sleep
conf.iface="virbr0" # set interface to wlp4s0
conf.verb = 0 # stop scapy from printing junk

mac_src = "00:00:00:00:00:00" # set source mac adress
mac_dst = "ff:ff:ff:ff:ff:ff" # set destination mac adress

# make ethernet headder
ether = Ether(src=mac_src, dst=mac_dst)

def mk_pkt(lttr):
    ip_addr = "10.10.200."+str(ord(lttr))
    arp = ARP(pdst=ip_addr) # make arp request
    packet = ether/arp # make packet
    sendp(packet) # send packet


msg = "horney goat weed"

for lttr in msg:
    mk_pkt(lttr)
    sleep(2)
