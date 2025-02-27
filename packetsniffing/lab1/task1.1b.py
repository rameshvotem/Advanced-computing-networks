#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
print_pkt.num_packets +=1
print("\n=========== packet: {} ========\n".format(print_pkt.num_packets))
  pkt.show()
  
print_pkt.num_packets = 0
#1.1 capture only ICMP packets
#pkt = sniff(iface='br-90a6c720403e', filter='icmp', prn=print_pkt)

#1.2 capture TCP that comes from a particular with destination port 23
pkt = sniff(iface='br-b76d1e127f55', filter='TCP && src host 10.9.0.6 && dst port 23', prn=print_pkt)
