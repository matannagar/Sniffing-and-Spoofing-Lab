1.	from scapy.all import *  

2.	print("sniffing packets")      
3.	def print_pkt(pkt):  
a.	pkt.show()      
4.	pkt = sniff(iface='br-dba6a6f86b96', fiter='dst net 128.230.0.0/16', prn=print_pkt)  
