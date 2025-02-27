#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
#print_pkt.num_packets +=1
# print("\n=========== packet: {} ========\n".format(print_pkt.num_packets))
  pkt.show()
  
#print_pkt.num_packets = 0
#1.2 capture TCP that comes from a particular with destination port 23
pkt = sniff(iface='br-6a1eb3c838d9', filter='net 128.230.0.0/16', prn=print_pkt)
