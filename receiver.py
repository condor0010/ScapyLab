from scapy.all import *

def pkt_callback(pkt):
    if pkt[ICMP].type==8:
        print("[+] Received Message: "+str(pkt[Raw].load))

print("[+] Started Listener")

sniff(iface="wlan0",prn=pkt_callback,filter='icmp',store=0)
