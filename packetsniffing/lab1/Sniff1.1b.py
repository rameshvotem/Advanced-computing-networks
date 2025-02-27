#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
#print_pkt.num_packets +=1
# print("\n=========== packet: {} ========\n".format(print_pkt.num_packets))
  pkt.show()
  
#print_pkt.num_packets = 0
#1.2 capture TCP that comes from a particular with destination port 23
pkt = sniff(iface='br-6a1eb3c838d9', filter='tcp && src host 10.9.0.6 && dst port 23', prn=print_pkt)
