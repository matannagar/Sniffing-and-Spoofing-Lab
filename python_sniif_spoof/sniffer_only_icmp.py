1.	from scapy.all import *  
2.	  
3.	print("sniffing packets")  
4.	  
5.	  
6.	def print_pkt(pkt):  
7.	    pkt.show()  
8.	  
9.	  
10.	pkt = sniff(iface='br-dba6a6f86b96', filter='icmp', prn=print_pkt)  
