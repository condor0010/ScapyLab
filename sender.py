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

# make arp request
arp = ARP(pdst="0.0.0.0")

# make packet
packet = ether/arp

# for testing will remove
wireshark (packet)

#sends packet
sendp(packet)

