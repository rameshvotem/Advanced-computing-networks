#!/usr/bin/env python3

from scapy.all import *
def print_pkt(pkt):
pkt.show()
pkt = sniff(iface=’br-6a1eb3c838d9’, filter=’icmp’, prn=print_pkt)
