#!/bin/python
from scapy.all import *

# interface names are difrent on my laptop
conf.iface="wlp4s0"

dst = "192.168.1.100"
msg = "adastra per explotium"

pkt = IP(dst=dst)/ICMP()/Raw(load=msg)
send(pkt)
