#!/usr/bin/env python3

from scapy.all import *
import sys

a = IP()
a.dst = '8.8.4.4'
a.ttl = int(sys.argv[1])
b = ICMP()

response = sr1(a/b, timeout=2, verbose=0)

if response:
    print("Source:", response.src)
else:
    print("No response received within the timeout period.")

