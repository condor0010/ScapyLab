from scapy.all import *

conf.iface="wlan0"

dst = "192.168.1.100"
msg = "adastra per explotium"

pkt = IP(dst=dst)/ICMP()/Raw(load=msg)
send(pkt)
