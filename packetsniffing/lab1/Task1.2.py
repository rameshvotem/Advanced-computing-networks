#!/usr/bin/env python3
from scapy.all import *
a = IP()
a.src = '4.3.2.1'
a.dst = '10.0.0.6'
ls(a)
send(a/ICMP()) 
