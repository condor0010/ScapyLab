from scapy.all import *
from operator import xor
import os
from scapy.layers.l2 import ARP, Ether

signal1 = "00:11:22:33:44:55"
signal2 = "aa:bb:cc:dd:ee:ff"

ip_dst = "127.0.0.1"
ip_src = '192.168.1.1'

msg = "adastra per explotium"


def gen_rng(size):
    return os.urandom(size)


def encode_char(c, key):
    return xor(c, key)


def test_msg(secret, key):
    print(gen_arp(secret, key).build())


def send_msg(secret, key):
    send(gen_arp(secret, key))


def gen_msg(keys, secrets):
    for c in msg:
        key = int.from_bytes(gen_key(), "little")
        secret = gen_secret(ord(c), key)
        keys.append(key)
        secrets.append(secret)


def gen_key():
    return gen_rng(1)


def gen_secret(c, key):
    return encode_char(c, key)


def gen_arp(macs):
    return Ether(dst=macs[0], src=macs[1]) / ARP(hwdst=macs[2], hwsrc=macs[3])


def f_byte(n):
    return format(n, '02x')


def gen_signal(mac1, mac2, op):
    return Ether(dst=mac1, src=mac2) / ARP(hwdst=mac2, hwsrc=mac1, op=op)


def gen_mac(secrets, keys):
    mac = []
    if len(secrets) == 3:
        for i in range(3):
            mac.append(f_byte(keys[i]))
            mac.append(f_byte(secrets[i]))
    else:
        for i in range(len(secrets)):
            mac.append(f_byte(keys[i]))
            mac.append(f_byte(secrets[i]))
        for i in range(3 - len(secrets)):
            mac.append("00")
            mac.append("00")
    return ':'.join(mac)


def main():
    keys = []
    secrets = []
    macs = []
    pkt = []
    start = gen_signal(signal1, signal2, 1)
    stop = gen_signal(signal2, signal1, 2)
    gen_msg(keys, secrets)
    for i in range(0, len(keys), 3):
        macs.append(gen_mac(secrets[i:i+3], keys[i:i+3]))

    if len(macs) % 4 != 0:
        for i in range(4 - len(macs) % 4):
            macs.append(gen_mac([], []))

    for i in range(0, len(macs), 4):
        pkt.append(gen_arp(macs[i:i+4]))

    sendp(start, iface="lo")

    for p in pkt:
        sendp(p, iface="lo")

    sendp(stop, iface="lo")


main()
