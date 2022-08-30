#!/bin/python
from scapy.all import *
from operator import xor
import os

conf.iface="wlp4s0" # set interface to wlp4s0
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


# TODO
# xor thing falco did, or something more complex
# replace msg varible with data stream from stdin Ex: cat boobs.txt | ./sender.py
# do recv file, works in wireshark so it should be fine
# pep 8 stuff i guess, mostly just want it to look nice and be easy to read
