from scapy.all import *
a = IP()
a.src = '10.2.3.0'
a.dst = '10.9.0.5'
b = ICMP()
send(a/b)