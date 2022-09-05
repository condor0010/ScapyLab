from scapy.all import *
from operator import xor
import os
from scapy.layers.l2 import ARP, Ether

signal1 = "00:11:22:33:44:55"
signal2 = "aa:bb:cc:dd:ee:ff"

ip_dst = "127.0.0.1"
ip_src = '192.168.1.1'

msg = "adastra per explotium"

msg_started = False
msg_stopped = False


def extract_macs(p):
    return [p[Ether].src, p[ARP].hwdst, p[ARP].hwsrc]


def stop_filter(p):
    global msg_stopped
    if p[Ether].src == p[ARP].hwdst == signal2 and p[ARP].hwsrc == signal1:
        msg_stopped = True
    return msg_stopped
    

def keep_packet(p):
    global msg_started
    if not msg_started:
        if p[Ether].src == p[ARP].hwdst == signal1 and p[ARP].hwsrc == signal2:
            msg_started = True


def start_sniffing():
    global msg_started
    pkt = sniff(
        filter="arp",
        prn=lambda x: keep_packet(x),
        # store=msg_started,
        stop_filter=lambda x: stop_filter(x),
        iface='lo')
    while not msg_started:
        pass
    return pkt


def str_to_int(s):
    return int(s, 16)


def xor_mac(mac):
    s = ''
    chars = mac.split(':')
    for i in range(3):
        char = xor(str_to_int(chars[i * 2]), str_to_int(chars[(i * 2) + 1]))
        s = s + chr(char)
    return s


def parse_packets(pkts):
    s = ''
    for pkt in pkts:
        if not msg_started:
            keep_packet(pkt)
        elif not stop_filter(pkt):
            for mac in extract_macs(pkt):
                s = s + xor_mac(mac)
    return s       


def main():
    print(parse_packets(start_sniffing))
